// Package mongo undoes and restores what the MongoDB gateway recorded. A record holds,
// for each document a transaction changed, its _id and its full content before and after,
// as canonical Extended JSON (every BSON type exact). Undo checks that each document is
// still as the transaction left it, then puts it back, all in one transaction: a document
// changed since is a conflict and nothing is written.
package mongo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"undolayer/internal/model"
	"undolayer/internal/tx"
	"undolayer/internal/vault"
)

// Change is one document's net change.
type Change struct {
	DB     string `json:"db"`
	Coll   string `json:"coll"`
	ID     string `json:"_id"`              // canonical Extended JSON of the _id
	Before string `json:"before,omitempty"` // canonical Extended JSON; empty: it did not exist
	After  string `json:"after,omitempty"`  // empty: it was deleted
}

// UndoRecord is what the gateway keeps for one transaction.
type UndoRecord struct {
	URI     string   `json:"uri"` // without the password
	Changes []Change `json:"changes"`
}

// Connector reaches the database the gateway is in front of.
type Connector struct {
	tx.Base
	URI string // with the gateway's credentials
}

func New(name, uri string) *Connector { return &Connector{Base: tx.Base{ConnName: name}, URI: uri} }

func (c *Connector) Hidden() bool { return true }

// Classify: the connector offers no operations to agents (it exists so that undo and
// restore can reach what the gateway recorded).
func (c *Connector) Classify(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	return model.Read, nil, fmt.Errorf("%s: no operations (the MongoDB gateway's connector)", c.Name())
}

func (c *Connector) client(ctx context.Context) (*mongo.Client, error) {
	return mongo.Connect(options.Client().ApplyURI(c.URI))
}

// Canon renders a document (or value) as canonical Extended JSON.
func Canon(v any) (string, error) {
	b, err := bson.MarshalExtJSON(v, true, false)
	return string(b), err
}

func parseDoc(s string) (bson.D, error) {
	var d bson.D
	err := bson.UnmarshalExtJSON([]byte(s), true, &d)
	return d, err
}

func parseID(s string) (any, error) {
	var w struct {
		ID any `bson:"_id"`
	}
	if err := bson.UnmarshalExtJSON([]byte(`{"_id":`+s+`}`), true, &w); err != nil {
		return nil, err
	}
	return w.ID, nil
}

func current(ctx context.Context, coll *mongo.Collection, id any) (string, error) {
	var raw bson.Raw
	err := coll.FindOne(ctx, bson.D{{Key: "_id", Value: id}}).Decode(&raw)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return Canon(raw)
}

// Undo puts every document back as it was before, if each is still as it was left.
func (c *Connector) Undo(raw json.RawMessage) error {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	return c.apply(rec.Changes, nil)
}

// apply puts back the chosen changes (all if pick is nil), newest first, in one transaction.
func (c *Connector) apply(changes []Change, pick func(Change) bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cl, err := c.client(ctx)
	if err != nil {
		return err
	}
	defer cl.Disconnect(ctx)
	sess, err := cl.StartSession()
	if err != nil {
		return err
	}
	defer sess.EndSession(ctx)
	_, err = sess.WithTransaction(ctx, func(ctx context.Context) (any, error) {
		for i := len(changes) - 1; i >= 0; i-- {
			ch := changes[i]
			if pick != nil && !pick(ch) {
				continue
			}
			coll := cl.Database(ch.DB).Collection(ch.Coll)
			id, err := parseID(ch.ID)
			if err != nil {
				return nil, err
			}
			now, err := current(ctx, coll, id)
			if err != nil {
				return nil, err
			}
			switch {
			case now == ch.Before:
				continue // already as it was
			case now != ch.After:
				return nil, model.Conflict("%s.%s %s changed after that transaction; refusing to put it back", ch.DB, ch.Coll, ch.ID)
			}
			switch {
			case ch.Before == "":
				_, err = coll.DeleteOne(ctx, bson.D{{Key: "_id", Value: id}})
			case ch.After == "":
				d, perr := parseDoc(ch.Before)
				if perr != nil {
					return nil, perr
				}
				_, err = coll.InsertOne(ctx, d)
			default:
				d, perr := parseDoc(ch.Before)
				if perr != nil {
					return nil, perr
				}
				_, err = coll.ReplaceOne(ctx, bson.D{{Key: "_id", Value: id}}, d)
			}
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	}, options.Transaction())
	var cc *model.CommitConflict
	if errors.As(err, &cc) {
		return cc
	}
	return err
}

// DescribeRows lists each changed document.
func (c *Connector) DescribeRows(raw json.RawMessage) ([]vault.Row, error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	var out []vault.Row
	for _, ch := range rec.Changes {
		r := vault.Row{Table: ch.DB + "." + ch.Coll, Key: map[string]any{"_id": jsonAny(ch.ID)}}
		switch {
		case ch.Before == "":
			r.Op = "insert"
		case ch.After == "":
			r.Op = "delete"
		default:
			r.Op = "update"
		}
		if ch.Before != "" {
			r.Before, _ = jsonAny(ch.Before).(map[string]any)
		}
		if ch.After != "" {
			r.After, _ = jsonAny(ch.After).(map[string]any)
		}
		out = append(out, r)
	}
	return out, nil
}

func jsonAny(s string) any {
	var v any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	_ = dec.Decode(&v)
	return v
}

// ResolveInFlight: whether a transaction recorded before its commit was committed, told
// from the documents themselves (all as after: committed; all as before: not).
func (c *Connector) ResolveInFlight(raw json.RawMessage) (committed, known bool, err error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return false, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cl, err := c.client(ctx)
	if err != nil {
		return false, false, err
	}
	defer cl.Disconnect(ctx)
	after, before := 0, 0
	for _, ch := range rec.Changes {
		id, err := parseID(ch.ID)
		if err != nil {
			return false, false, err
		}
		now, err := current(ctx, cl.Database(ch.DB).Collection(ch.Coll), id)
		if err != nil {
			return false, false, err
		}
		if now == ch.After {
			after++
		}
		if now == ch.Before {
			before++
		}
	}
	switch {
	case after == len(rec.Changes) && before == 0:
		return true, true, nil
	case before == len(rec.Changes) && after == 0:
		return false, true, nil
	}
	return false, false, nil
}

// Operations: restore_docs puts chosen documents back (a new task that is checked and
// undoable is the SQL connectors' way; for MongoDB a restore is applied directly, in one
// transaction, after the same check).
func (c *Connector) Operations() map[string]tx.OpSchema { return nil }

// RestoreDocs puts back the documents of a recorded transaction that match keys (by
// canonical _id) or collections, checking each as Undo does.
func (c *Connector) RestoreDocs(raw json.RawMessage, colls map[string]bool, ids map[string]bool) (int, error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return 0, err
	}
	n := 0
	pick := func(ch Change) bool {
		ok := (len(colls) == 0 || colls[ch.DB+"."+ch.Coll] || colls[ch.Coll]) && (len(ids) == 0 || ids[ch.ID])
		if ok {
			n++
		}
		return ok
	}
	err := c.apply(rec.Changes, pick)
	return n, err
}

// SortChanges orders changes by collection then _id (stable output).
func SortChanges(cs []Change) {
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].DB+cs[i].Coll != cs[j].DB+cs[j].Coll {
			return cs[i].DB+cs[i].Coll < cs[j].DB+cs[j].Coll
		}
		return cs[i].ID < cs[j].ID
	})
}
