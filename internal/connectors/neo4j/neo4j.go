// Package neo4j captures, undoes and restores graph changes made through the Neo4j gateway.
//
// Capture is an APOC trigger in the before-commit phase, installed by the gateway. Inside
// the committing transaction it sends what the transaction changed to the gateway: created
// nodes and relationships, deleted ones (their labels, type, endpoints and properties),
// and every property and label assigned or removed, with old values. Every value carries
// its Cypher type, so dates, durations and integers come back as what they were. The
// gateway stores the change in the vault and answers; if it refuses, or cannot store it on
// a quorum, the trigger fails and the transaction does not commit.
package neo4j

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"undolayer/internal/model"
	"undolayer/internal/tx"
	"undolayer/internal/vault"
)

// TV is a typed value: its Cypher type (apoc.meta.cypher.type) and its JSON value.
type TV struct {
	T string          `json:"t"`
	V json.RawMessage `json:"v"`
}

// State is a node's labels (or a relationship's type) and properties.
type State struct {
	Labels []string      `json:"labels,omitempty"`
	Props  map[string]TV `json:"props"`
}

// Entity is one node's or relationship's net change (Before or After nil: it did not
// exist before, or no longer does).
type Entity struct {
	Rel    bool   `json:"rel,omitempty"`
	ID     string `json:"id"`
	Type   string `json:"type,omitempty"`  // relationship type
	Start  string `json:"start,omitempty"` // relationship endpoints
	End    string `json:"end,omitempty"`
	Before *State `json:"before,omitempty"`
	After  *State `json:"after,omitempty"`
}

// UndoRecord is what the gateway keeps for one transaction.
type UndoRecord struct {
	DB       string   `json:"db"`
	Entities []Entity `json:"entities"`
}

// typed renders a property map with each value's type.
func typed(m string) string {
	return "apoc.map.fromPairs([k IN keys(" + m + ") | [k, {t: apoc.meta.cypher.type(" + m + "[k]), v: " + m + "[k]}]])"
}

func tv(v string) string { return "{t: apoc.meta.cypher.type(" + v + "), v: " + v + "}" }

// TriggerStatement is the before-commit trigger: it posts the transaction's changes to url.
func TriggerStatement(url string) string {
	changedNodes := "apoc.coll.toSet(apoc.coll.flatten([k IN keys($assignedNodeProperties) | [e IN $assignedNodeProperties[k] | e.node]] + " +
		"[k IN keys($removedNodeProperties) | [e IN $removedNodeProperties[k] | e.node]] + " +
		"[k IN keys($assignedLabels) | $assignedLabels[k]] + [k IN keys($removedLabels) | $removedLabels[k]]))"
	changedRels := "apoc.coll.toSet(apoc.coll.flatten([k IN keys($assignedRelationshipProperties) | [e IN $assignedRelationshipProperties[k] | e.relationship]] + " +
		"[k IN keys($removedRelationshipProperties) | [e IN $removedRelationshipProperties[k] | e.relationship]]))"
	props := func(list, ent string) string {
		return "apoc.coll.flatten([k IN keys(" + list + ") | [e IN " + list + "[k] | {id: elementId(e." + ent + "), k: e.key, old: " + tv("e.old") + "}]])"
	}
	return "WITH $metaData AS md WHERE md.countersign_key IS NOT NULL " +
		"WITH md, [n IN $deletedNodes | elementId(n)] AS dn, [r IN $deletedRelationships | elementId(r)] AS dr, " +
		"[n IN $createdNodes | elementId(n)] AS cnid, [r IN $createdRelationships | elementId(r)] AS crid " +
		"CALL apoc.load.jsonParams(" + quote(url) + ", {`X-Countersign-Key`: md.countersign_key}, apoc.convert.toJson({" +
		"cnid: cnid, crid: crid, cn: [n IN $createdNodes WHERE NOT elementId(n) IN dn | {id: elementId(n), labels: labels(n), props: " + typed("properties(n)") + "}], " +
		"cr: [r IN $createdRelationships WHERE NOT elementId(r) IN dr | {id: elementId(r), type: type(r), s: elementId(startNode(r)), e: elementId(endNode(r)), props: " + typed("properties(r)") + "}], " +
		"dn: dn, " +
		"dr: [r IN $deletedRelationships | {id: elementId(r), type: type(r), s: elementId(startNode(r)), e: elementId(endNode(r))}], " +
		"anp: " + props("$assignedNodeProperties", "node") + ", " +
		"rnp: " + props("$removedNodeProperties", "node") + ", " +
		"arp: " + props("$assignedRelationshipProperties", "relationship") + ", " +
		"rrp: " + props("$removedRelationshipProperties", "relationship") + ", " +
		"al: [k IN keys($assignedLabels) | {l: k, ids: [n IN $assignedLabels[k] | elementId(n)]}], " +
		"rl: [k IN keys($removedLabels) | {l: k, ids: [n IN $removedLabels[k] | elementId(n)]}], " +
		"mn: [n IN " + changedNodes + " WHERE NOT elementId(n) IN dn AND NOT elementId(n) IN cnid | {id: elementId(n), labels: labels(n), props: " + typed("properties(n)") + "}], " +
		"mr: [r IN " + changedRels + " WHERE NOT elementId(r) IN dr AND NOT elementId(r) IN crid | {id: elementId(r), type: type(r), s: elementId(startNode(r)), e: elementId(endNode(r)), props: " + typed("properties(r)") + "}]" +
		"})) YIELD value RETURN value"
}

func quote(s string) string { return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'" }

// Payload is what the trigger sends.
type Payload struct {
	CNID []string `json:"cnid"`
	CRID []string `json:"crid"`
	CN   []struct {
		ID     string        `json:"id"`
		Labels []string      `json:"labels"`
		Props  map[string]TV `json:"props"`
	} `json:"cn"`
	CR  []relJSON `json:"cr"`
	DN  []string  `json:"dn"`
	DR  []relJSON `json:"dr"`
	ANP []propOld `json:"anp"`
	RNP []propOld `json:"rnp"`
	ARP []propOld `json:"arp"`
	RRP []propOld `json:"rrp"`
	AL  []labels  `json:"al"`
	RL  []labels  `json:"rl"`
	MN  []struct {
		ID     string        `json:"id"`
		Labels []string      `json:"labels"`
		Props  map[string]TV `json:"props"`
	} `json:"mn"`
	MR []relJSON `json:"mr"`
}

type relJSON struct {
	ID    string        `json:"id"`
	Type  string        `json:"type"`
	S     string        `json:"s"`
	E     string        `json:"e"`
	Props map[string]TV `json:"props"`
}

type propOld struct {
	ID  string `json:"id"`
	K   string `json:"k"`
	Old TV     `json:"old"`
}

type labels struct {
	L   string   `json:"l"`
	IDs []string `json:"ids"`
}

func copyProps(m map[string]TV) map[string]TV {
	out := map[string]TV{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func restoreOld(props map[string]TV, k string, old TV) {
	if old.T == "NULL" || old.T == "" {
		delete(props, k)
	} else {
		props[k] = old
	}
}

// Changes turns the trigger's payload into each entity's state before and after.
func (p *Payload) Changes() []Entity {
	var out []Entity
	for _, n := range p.CN {
		out = append(out, Entity{ID: n.ID, After: &State{Labels: sorted(n.Labels), Props: n.Props}})
	}
	for _, r := range p.CR {
		out = append(out, Entity{Rel: true, ID: r.ID, Type: r.Type, Start: r.S, End: r.E, After: &State{Props: r.Props}})
	}
	// nodes changed in place: their state now, with every change taken back
	for _, n := range p.MN {
		before := &State{Labels: append([]string{}, n.Labels...), Props: copyProps(n.Props)}
		for _, e := range p.ANP {
			if e.ID == n.ID {
				restoreOld(before.Props, e.K, e.Old)
			}
		}
		for _, e := range p.RNP {
			if e.ID == n.ID {
				restoreOld(before.Props, e.K, e.Old)
			}
		}
		for _, l := range p.AL {
			if contains(l.IDs, n.ID) {
				before.Labels = remove(before.Labels, l.L)
			}
		}
		for _, l := range p.RL {
			if contains(l.IDs, n.ID) && !contains(before.Labels, l.L) {
				before.Labels = append(before.Labels, l.L)
			}
		}
		before.Labels = sorted(before.Labels)
		out = append(out, Entity{ID: n.ID, Before: before, After: &State{Labels: sorted(n.Labels), Props: n.Props}})
	}
	for _, r := range p.MR {
		before := &State{Props: copyProps(r.Props)}
		for _, e := range append(append([]propOld{}, p.ARP...), p.RRP...) {
			if e.ID == r.ID {
				restoreOld(before.Props, e.K, e.Old)
			}
		}
		out = append(out, Entity{Rel: true, ID: r.ID, Type: r.Type, Start: r.S, End: r.E, Before: before, After: &State{Props: r.Props}})
	}
	// deleted: what they were, from the labels and properties removed with them (those
	// created in this same transaction changed nothing)
	for _, id := range p.DN {
		if contains(p.CNID, id) {
			continue
		}
		before := &State{Props: map[string]TV{}}
		for _, e := range p.RNP {
			if e.ID == id {
				before.Props[e.K] = e.Old
			}
		}
		for _, l := range p.RL {
			if contains(l.IDs, id) {
				before.Labels = append(before.Labels, l.L)
			}
		}
		before.Labels = sorted(before.Labels)
		out = append(out, Entity{ID: id, Before: before})
	}
	for _, r := range p.DR {
		if contains(p.CRID, r.ID) {
			continue
		}
		before := &State{Props: map[string]TV{}}
		for _, e := range p.RRP {
			if e.ID == r.ID {
				before.Props[e.K] = e.Old
			}
		}
		out = append(out, Entity{Rel: true, ID: r.ID, Type: r.Type, Start: r.S, End: r.E, Before: before})
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func remove(xs []string, x string) []string {
	var out []string
	for _, y := range xs {
		if y != x {
			out = append(out, y)
		}
	}
	return out
}

func sorted(xs []string) []string {
	out := append([]string{}, xs...)
	sort.Strings(out)
	return out
}

// Canon renders a state comparably.
func Canon(s *State) string {
	if s == nil {
		return ""
	}
	type kv struct {
		K string
		T string
		V string
	}
	var ps []kv
	for k, v := range s.Props {
		ps = append(ps, kv{k, v.T, canonJSON(v.V)})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].K < ps[j].K })
	b, _ := json.Marshal(struct {
		L []string
		P []kv
	}{sorted(s.Labels), ps})
	return string(b)
}

func canonJSON(b json.RawMessage) string {
	var v any
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return string(b)
	}
	out, _ := json.Marshal(v)
	return string(out)
}

// Connector reaches the database the gateway is in front of.
type Connector struct {
	tx.Base
	URI, User, Password string
}

func New(name, uri, user, password string) *Connector {
	return &Connector{Base: tx.Base{ConnName: name}, URI: uri, User: user, Password: password}
}

func (c *Connector) Hidden() bool { return true }

func (c *Connector) Classify(t *tx.Tx, op string, args map[string]any) (model.Effect, model.Facts, error) {
	return model.Read, nil, fmt.Errorf("%s: no operations (the Neo4j gateway's connector)", c.Name())
}

func (c *Connector) driver() (neo4j.DriverWithContext, error) {
	return neo4j.NewDriverWithContext(c.URI, neo4j.BasicAuth(c.User, c.Password, ""))
}

// the typed value in Cypher: what param p ({t, v}) holds, as its own type
const fromTV = "CASE p.t WHEN 'DATE' THEN date(p.v) WHEN 'DATE_TIME' THEN datetime(p.v) WHEN 'LOCAL_DATE_TIME' THEN localdatetime(p.v) " +
	"WHEN 'TIME' THEN time(p.v) WHEN 'LOCAL_TIME' THEN localtime(p.v) WHEN 'DURATION' THEN duration(p.v) " +
	"WHEN 'POINT' THEN point(p.v) ELSE p.v END"

const propMap = "apoc.map.fromPairs([p IN $props | [p.k, " + fromTV + "]])"

// params turns a state's properties into what the Cypher above reads.
func params(s *State) ([]any, error) {
	var out []any
	for k, v := range s.Props {
		val, err := goValue(v)
		if err != nil {
			return nil, fmt.Errorf("property %s: %v", k, err)
		}
		out = append(out, map[string]any{"k": k, "t": v.T, "v": val})
	}
	return out, nil
}

func goValue(v TV) (any, error) {
	d := json.NewDecoder(strings.NewReader(string(v.V)))
	d.UseNumber()
	var x any
	if err := d.Decode(&x); err != nil {
		return nil, err
	}
	return convert(x, v.T)
}

func convert(x any, t string) (any, error) {
	switch {
	case strings.HasPrefix(t, "LIST"):
		arr, _ := x.([]any)
		elem := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(t, "LIST"), " OF"))
		out := make([]any, 0, len(arr))
		for _, e := range arr {
			ce, err := convert(e, elem)
			if err != nil {
				return nil, err
			}
			out = append(out, ce)
		}
		return out, nil
	case t == "INTEGER":
		n, ok := x.(json.Number)
		if !ok {
			return nil, errors.New("not an integer")
		}
		return n.Int64()
	case t == "FLOAT":
		n, ok := x.(json.Number)
		if !ok {
			return nil, errors.New("not a number")
		}
		return n.Float64()
	case t == "POINT":
		m, _ := x.(map[string]any)
		out := map[string]any{}
		for _, k := range []string{"crs", "x", "y", "z"} {
			if v, ok := m[k]; ok && v != nil {
				if n, ok := v.(json.Number); ok {
					f, _ := n.Float64()
					out[k] = f
				} else {
					out[k] = v
				}
			}
		}
		return out, nil
	}
	if n, ok := x.(json.Number); ok {
		return n.Float64()
	}
	return x, nil
}

// the state of an entity now, rendered as the trigger renders it
func current(ctx context.Context, t neo4j.ExplicitTransaction, e Entity, id string) (*State, error) {
	q := "MATCH (n) WHERE elementId(n) = $id RETURN apoc.convert.toJson({labels: labels(n), props: " + typed("properties(n)") + "})"
	if e.Rel {
		q = "MATCH ()-[n]->() WHERE elementId(n) = $id RETURN apoc.convert.toJson({props: " + typed("properties(n)") + "})"
	}
	res, err := t.Run(ctx, q, map[string]any{"id": id})
	if err != nil {
		return nil, err
	}
	rec, err := res.Single(ctx)
	if err != nil {
		return nil, nil // not there
	}
	s, _ := rec.Values[0].(string)
	var st State
	if err := json.Unmarshal([]byte(s), &st); err != nil {
		return nil, err
	}
	st.Labels = sorted(st.Labels)
	if st.Props == nil {
		st.Props = map[string]TV{}
	}
	return &st, nil
}

// Undo puts the graph back as it was before the transaction, if everything it changed is
// still as it left it. Deleted nodes and relationships come back as new ones (Neo4j gives
// them new element ids), with their labels, types, properties and connections.
func (c *Connector) Undo(raw json.RawMessage) error {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	_, err := c.apply(&rec, nil)
	return err
}

func (c *Connector) apply(rec *UndoRecord, pick func(Entity) bool) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	d, err := c.driver()
	if err != nil {
		return 0, err
	}
	defer d.Close(ctx)
	sess := d.NewSession(ctx, neo4j.SessionConfig{DatabaseName: rec.DB, AccessMode: neo4j.AccessModeWrite})
	defer sess.Close(ctx)
	t, err := sess.BeginTransaction(ctx)
	if err != nil {
		return 0, err
	}
	defer t.Close(ctx)
	run := func(q string, p map[string]any) error {
		res, err := t.Run(ctx, q, p)
		if err != nil {
			return err
		}
		_, err = res.Consume(ctx)
		return err
	}
	var es []Entity
	for _, e := range rec.Entities {
		if pick == nil || pick(e) {
			es = append(es, e)
		}
	}
	created := map[string]bool{}
	for _, e := range es {
		if e.Before == nil {
			created[e.ID] = true
		}
	}
	// everything the transaction left must still be as it left it
	for _, e := range es {
		if e.After == nil {
			continue
		}
		now, err := current(ctx, t, e, e.ID)
		if err != nil {
			return 0, err
		}
		if Canon(now) != Canon(e.After) {
			kind := "node"
			if e.Rel {
				kind = "relationship"
			}
			return 0, model.Conflict("%s %s changed after that transaction; refusing to put it back", kind, e.ID)
		}
	}
	n := 0
	// relationships it created go; then nodes it created, if nothing else connects to them now
	for _, e := range es {
		if e.Rel && e.Before == nil {
			if err := run("MATCH ()-[r]->() WHERE elementId(r) = $id DELETE r", map[string]any{"id": e.ID}); err != nil {
				return 0, err
			}
			n++
		}
	}
	for _, e := range es {
		if !e.Rel && e.Before == nil {
			res, err := t.Run(ctx, "MATCH (n) WHERE elementId(n) = $id OPTIONAL MATCH (n)-[x]-() RETURN count(x)", map[string]any{"id": e.ID})
			if err != nil {
				return 0, err
			}
			r, err := res.Single(ctx)
			if err != nil {
				return 0, err
			}
			if k, _ := r.Values[0].(int64); k > 0 {
				return 0, model.Conflict("node %s has relationships made after that transaction; refusing to delete it", e.ID)
			}
			if err := run("MATCH (n) WHERE elementId(n) = $id DELETE n", map[string]any{"id": e.ID}); err != nil {
				return 0, err
			}
			n++
		}
	}
	// what it changed in place goes back
	for _, e := range es {
		if e.Before == nil || e.After == nil {
			continue
		}
		ps, err := params(e.Before)
		if err != nil {
			return 0, err
		}
		if e.Rel {
			err = run("MATCH ()-[r]->() WHERE elementId(r) = $id SET r = "+propMap, map[string]any{"id": e.ID, "props": ps})
		} else {
			err = run("MATCH (n) WHERE elementId(n) = $id SET n = "+propMap+" WITH n CALL apoc.create.setLabels(n, $labels) YIELD node RETURN count(node)",
				map[string]any{"id": e.ID, "props": ps, "labels": strs(e.Before.Labels)})
		}
		if err != nil {
			return 0, err
		}
		n++
	}
	// what it deleted comes back: nodes first, then the relationships between them
	newID := map[string]string{}
	for _, e := range es {
		if e.Rel || e.After != nil {
			continue
		}
		ps, err := params(e.Before)
		if err != nil {
			return 0, err
		}
		res, err := t.Run(ctx, "CALL apoc.create.node($labels, "+propMap+") YIELD node RETURN elementId(node)",
			map[string]any{"labels": strs(e.Before.Labels), "props": ps})
		if err != nil {
			return 0, err
		}
		r, err := res.Single(ctx)
		if err != nil {
			return 0, err
		}
		newID[e.ID], _ = r.Values[0].(string)
		n++
	}
	for _, e := range es {
		if !e.Rel || e.After != nil {
			continue
		}
		s, en := e.Start, e.End
		if v, ok := newID[s]; ok {
			s = v
		}
		if v, ok := newID[en]; ok {
			en = v
		}
		ps, err := params(e.Before)
		if err != nil {
			return 0, err
		}
		res, err := t.Run(ctx, "MATCH (a), (b) WHERE elementId(a) = $s AND elementId(b) = $e "+
			"CALL apoc.create.relationship(a, $type, "+propMap+", b) YIELD rel RETURN count(rel)",
			map[string]any{"s": s, "e": en, "type": e.Type, "props": ps})
		if err != nil {
			return 0, err
		}
		r, err := res.Single(ctx)
		if err != nil {
			return 0, err
		}
		if k, _ := r.Values[0].(int64); k != 1 {
			return 0, model.Conflict("relationship %s: its endpoints are gone; refusing to put it back", e.ID)
		}
		n++
	}
	if err := t.Commit(ctx); err != nil {
		return 0, err
	}
	return n, nil
}

func strs(xs []string) []any {
	out := make([]any, 0, len(xs))
	for _, x := range xs {
		out = append(out, x)
	}
	return out
}

// DescribeRows lists each changed entity (table: "node" or the relationship type).
func (c *Connector) DescribeRows(raw json.RawMessage) ([]vault.Row, error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	var out []vault.Row
	for _, e := range rec.Entities {
		r := vault.Row{Table: "node", Key: map[string]any{"element_id": e.ID}}
		if e.Rel {
			r.Table = "relationship:" + e.Type
		} else if s := e.After; s != nil && len(s.Labels) > 0 {
			r.Table = "node:" + strings.Join(s.Labels, ":")
		} else if s := e.Before; s != nil && len(s.Labels) > 0 {
			r.Table = "node:" + strings.Join(s.Labels, ":")
		}
		switch {
		case e.Before == nil:
			r.Op = "insert"
		case e.After == nil:
			r.Op = "delete"
		default:
			r.Op = "update"
		}
		r.Before, r.After = plain(e.Before), plain(e.After)
		out = append(out, r)
	}
	return out, nil
}

func plain(s *State) map[string]any {
	if s == nil {
		return nil
	}
	m := map[string]any{}
	for k, v := range s.Props {
		var x any
		_ = json.Unmarshal(v.V, &x)
		m[k] = x
	}
	if len(s.Labels) > 0 {
		m[":labels"] = s.Labels
	}
	return m
}

// ResolveInFlight: committed if everything is as after, not if everything is as before.
func (c *Connector) ResolveInFlight(raw json.RawMessage) (committed, known bool, err error) {
	var rec UndoRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return false, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := c.driver()
	if err != nil {
		return false, false, err
	}
	defer d.Close(ctx)
	sess := d.NewSession(ctx, neo4j.SessionConfig{DatabaseName: rec.DB, AccessMode: neo4j.AccessModeRead})
	defer sess.Close(ctx)
	t, err := sess.BeginTransaction(ctx)
	if err != nil {
		return false, false, err
	}
	defer t.Close(ctx)
	after, before := 0, 0
	for _, e := range rec.Entities {
		now, err := current(ctx, t, e, e.ID)
		if err != nil {
			return false, false, err
		}
		if Canon(now) == Canon(e.After) {
			after++
		}
		if Canon(now) == Canon(e.Before) {
			before++
		}
	}
	switch {
	case after == len(rec.Entities) && before == 0:
		return true, true, nil
	case before == len(rec.Entities) && after == 0:
		return false, true, nil
	}
	return false, false, nil
}
