package mongogw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// MongoDB wire protocol: a 16-byte header (length, requestID, responseTo, opCode), then the
// body. Drivers speak OP_MSG (2013); OP_QUERY (2004) is only used for the first hello of
// old drivers, answered with OP_REPLY (1). Compression is never negotiated through the
// gateway (it strips the client's compressors), so OP_COMPRESSED does not occur.

const (
	opReply      = 1
	opQuery      = 2004
	opCompressed = 2012
	opMsg        = 2013

	flagChecksum    = 1 << 0
	flagMoreToCome  = 1 << 1
	flagExhaustOK   = 1 << 16
	maxMessageBytes = 48 << 20
)

type header struct {
	length, requestID, responseTo, opCode int32
}

type message struct {
	h    header
	body []byte // everything after the header
}

func readMessage(r io.Reader) (*message, error) {
	var hb [16]byte
	if _, err := io.ReadFull(r, hb[:]); err != nil {
		return nil, err
	}
	h := header{int32(binary.LittleEndian.Uint32(hb[0:])), int32(binary.LittleEndian.Uint32(hb[4:])),
		int32(binary.LittleEndian.Uint32(hb[8:])), int32(binary.LittleEndian.Uint32(hb[12:]))}
	if h.length < 16 || h.length > maxMessageBytes {
		return nil, fmt.Errorf("message length %d out of range", h.length)
	}
	body := make([]byte, h.length-16)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return &message{h: h, body: body}, nil
}

func (m *message) bytes() []byte {
	out := make([]byte, 16+len(m.body))
	binary.LittleEndian.PutUint32(out[0:], uint32(16+len(m.body)))
	binary.LittleEndian.PutUint32(out[4:], uint32(m.h.requestID))
	binary.LittleEndian.PutUint32(out[8:], uint32(m.h.responseTo))
	binary.LittleEndian.PutUint32(out[12:], uint32(m.h.opCode))
	copy(out[16:], m.body)
	return out
}

// opmsg is a parsed OP_MSG: its body document, and document sequences (kind 1 sections,
// e.g. "documents" of insert) by identifier.
type opmsg struct {
	flags uint32
	body  bson.Raw
	seqs  []docSeq
}

type docSeq struct {
	id   string
	docs []bson.Raw
}

func parseMsg(b []byte) (*opmsg, error) {
	if len(b) < 5 {
		return nil, errors.New("OP_MSG too short")
	}
	m := &opmsg{flags: binary.LittleEndian.Uint32(b)}
	end := len(b)
	if m.flags&flagChecksum != 0 {
		end -= 4
	}
	p := 4
	for p < end {
		kind := b[p]
		p++
		switch kind {
		case 0:
			if p+4 > end {
				return nil, errors.New("truncated body section")
			}
			n := int(binary.LittleEndian.Uint32(b[p:]))
			if n < 5 || p+n > end {
				return nil, errors.New("bad body section")
			}
			m.body = bson.Raw(append([]byte{}, b[p:p+n]...))
			p += n
		case 1:
			if p+4 > end {
				return nil, errors.New("truncated document sequence")
			}
			n := int(binary.LittleEndian.Uint32(b[p:]))
			if n < 4 || p+n > end {
				return nil, errors.New("bad document sequence")
			}
			sec := b[p+4 : p+n]
			i := 0
			for i < len(sec) && sec[i] != 0 {
				i++
			}
			if i >= len(sec) {
				return nil, errors.New("document sequence without an identifier")
			}
			ds := docSeq{id: string(sec[:i])}
			rest := sec[i+1:]
			for len(rest) > 0 {
				if len(rest) < 5 {
					return nil, errors.New("truncated document")
				}
				dn := int(binary.LittleEndian.Uint32(rest))
				if dn < 5 || dn > len(rest) {
					return nil, errors.New("bad document")
				}
				ds.docs = append(ds.docs, bson.Raw(append([]byte{}, rest[:dn]...)))
				rest = rest[dn:]
			}
			m.seqs = append(m.seqs, ds)
			p += n
		default:
			return nil, fmt.Errorf("unknown OP_MSG section kind %d", kind)
		}
	}
	if m.body == nil {
		return nil, errors.New("OP_MSG without a body")
	}
	return m, nil
}

// encode builds the OP_MSG body (no checksum: the gateway re-frames every message).
func (m *opmsg) encode() []byte {
	out := make([]byte, 4, 64+len(m.body))
	binary.LittleEndian.PutUint32(out, m.flags&^flagChecksum)
	out = append(out, 0)
	out = append(out, m.body...)
	for _, s := range m.seqs {
		var sec []byte
		sec = append(sec, s.id...)
		sec = append(sec, 0)
		for _, d := range s.docs {
			sec = append(sec, d...)
		}
		out = append(out, 1)
		var n [4]byte
		binary.LittleEndian.PutUint32(n[:], uint32(4+len(sec)))
		out = append(out, n[:]...)
		out = append(out, sec...)
	}
	return out
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// checksumOK verifies an OP_MSG's CRC-32C, when it has one.
func checksumOK(full []byte, flags uint32) bool {
	if flags&flagChecksum == 0 || len(full) < 20 {
		return true
	}
	want := binary.LittleEndian.Uint32(full[len(full)-4:])
	return crc32.Checksum(full[:len(full)-4], castagnoli) == want
}

// command is the merged view of an OP_MSG: the body with each document sequence put in as
// an array (as the server sees it).
func (m *opmsg) command() (bson.D, error) {
	var d bson.D
	if err := bson.Unmarshal(m.body, &d); err != nil {
		return nil, err
	}
	for _, s := range m.seqs {
		arr := bson.A{}
		for _, x := range s.docs {
			arr = append(arr, x)
		}
		d = append(d, bson.E{Key: s.id, Value: arr})
	}
	return d, nil
}

func newMsg(cmd bson.D, flags uint32) (*opmsg, error) {
	b, err := bson.Marshal(cmd)
	if err != nil {
		return nil, err
	}
	return &opmsg{flags: flags, body: b}, nil
}

// parseQuery reads an OP_QUERY: flags, full collection name, skip, return, the query.
func parseQuery(b []byte) (coll string, query bson.Raw, err error) {
	if len(b) < 4 {
		return "", nil, errors.New("OP_QUERY too short")
	}
	i := 4
	for i < len(b) && b[i] != 0 {
		i++
	}
	if i+9 > len(b) {
		return "", nil, errors.New("bad OP_QUERY")
	}
	coll = string(b[4:i])
	p := i + 1 + 8
	if p+4 > len(b) {
		return "", nil, errors.New("bad OP_QUERY")
	}
	n := int(binary.LittleEndian.Uint32(b[p:]))
	if n < 5 || p+n > len(b) {
		return "", nil, errors.New("bad OP_QUERY document")
	}
	return coll, bson.Raw(b[p : p+n]), nil
}

// reply builds an OP_REPLY holding one document.
func reply(doc bson.Raw) []byte {
	out := make([]byte, 20)
	binary.LittleEndian.PutUint32(out[0:], 8) // AwaitCapable
	binary.LittleEndian.PutUint32(out[12:], 0)
	binary.LittleEndian.PutUint32(out[16:], 1) // numberReturned
	return append(out, doc...)
}
