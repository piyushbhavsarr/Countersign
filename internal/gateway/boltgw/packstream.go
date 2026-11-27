package boltgw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
)

// PackStream, Bolt's encoding: null, booleans, integers, floats, bytes, strings, lists,
// maps and structures (a tag and fields). Messages are structures; on the wire each is
// split into chunks (a 2-byte length, then that many bytes) and ended by an empty chunk.

type Struct struct {
	Tag    byte
	Fields []any
}

func readMessage(r io.Reader) ([]byte, error) {
	var msg []byte
	var hdr [2]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n == 0 {
			if len(msg) == 0 {
				continue // a keep-alive
			}
			return msg, nil
		}
		if len(msg)+n > 256<<20 {
			return nil, errors.New("message too large")
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		msg = append(msg, buf...)
	}
}

func frame(msg []byte) []byte {
	out := make([]byte, 0, len(msg)+len(msg)/65535*2+4)
	for len(msg) > 0 {
		n := min(len(msg), 65535)
		out = append(out, byte(n>>8), byte(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return append(out, 0, 0)
}

// tagOf reads a message's structure tag without decoding it.
func tagOf(msg []byte) byte {
	if len(msg) < 2 || msg[0]&0xF0 != 0xB0 {
		return 0
	}
	return msg[1]
}

type decoder struct {
	b []byte
	p int
}

func decode(b []byte) (any, error) {
	d := &decoder{b: b}
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (d *decoder) need(n int) error {
	if d.p+n > len(d.b) {
		return errors.New("packstream: truncated")
	}
	return nil
}

func (d *decoder) uint(n int) (uint64, error) {
	if err := d.need(n); err != nil {
		return 0, err
	}
	var v uint64
	for i := 0; i < n; i++ {
		v = v<<8 | uint64(d.b[d.p+i])
	}
	d.p += n
	return v, nil
}

func (d *decoder) value(depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("packstream: nested too deep")
	}
	if err := d.need(1); err != nil {
		return nil, err
	}
	m := d.b[d.p]
	d.p++
	switch {
	case m < 0x80:
		return int64(m), nil
	case m >= 0xF0:
		return int64(int8(m)), nil
	case m&0xF0 == 0x80:
		return d.str(int(m & 0x0F))
	case m&0xF0 == 0x90:
		return d.list(int(m&0x0F), depth)
	case m&0xF0 == 0xA0:
		return d.dict(int(m&0x0F), depth)
	case m&0xF0 == 0xB0:
		return d.structure(int(m&0x0F), depth)
	}
	switch m {
	case 0xC0:
		return nil, nil
	case 0xC2:
		return false, nil
	case 0xC3:
		return true, nil
	case 0xC1:
		u, err := d.uint(8)
		return math.Float64frombits(u), err
	case 0xC8:
		u, err := d.uint(1)
		return int64(int8(u)), err
	case 0xC9:
		u, err := d.uint(2)
		return int64(int16(u)), err
	case 0xCA:
		u, err := d.uint(4)
		return int64(int32(u)), err
	case 0xCB:
		u, err := d.uint(8)
		return int64(u), err
	case 0xCC, 0xCD, 0xCE:
		n, err := d.uint(1 << (m - 0xCC))
		if err != nil {
			return nil, err
		}
		if err := d.need(int(n)); err != nil {
			return nil, err
		}
		b := append([]byte{}, d.b[d.p:d.p+int(n)]...)
		d.p += int(n)
		return b, nil
	case 0xD0, 0xD1, 0xD2:
		n, err := d.uint(1 << (m - 0xD0))
		if err != nil {
			return nil, err
		}
		return d.str(int(n))
	case 0xD4, 0xD5, 0xD6:
		n, err := d.uint(1 << (m - 0xD4))
		if err != nil {
			return nil, err
		}
		return d.list(int(n), depth)
	case 0xD8, 0xD9, 0xDA:
		n, err := d.uint(1 << (m - 0xD8))
		if err != nil {
			return nil, err
		}
		return d.dict(int(n), depth)
	}
	return nil, fmt.Errorf("packstream: unknown marker %#x", m)
}

func (d *decoder) str(n int) (string, error) {
	if err := d.need(n); err != nil {
		return "", err
	}
	s := string(d.b[d.p : d.p+n])
	d.p += n
	return s, nil
}

func (d *decoder) list(n, depth int) ([]any, error) {
	if n > len(d.b) {
		return nil, errors.New("packstream: bad list")
	}
	out := make([]any, 0, n)
	for i := 0; i < n; i++ {
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (d *decoder) dict(n, depth int) (map[string]any, error) {
	if n > len(d.b) {
		return nil, errors.New("packstream: bad map")
	}
	out := make(map[string]any, n)
	for i := 0; i < n; i++ {
		k, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		ks, ok := k.(string)
		if !ok {
			return nil, errors.New("packstream: map key is not a string")
		}
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out[ks] = v
	}
	return out, nil
}

func (d *decoder) structure(n, depth int) (*Struct, error) {
	if err := d.need(1); err != nil {
		return nil, err
	}
	s := &Struct{Tag: d.b[d.p]}
	d.p++
	for i := 0; i < n; i++ {
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		s.Fields = append(s.Fields, v)
	}
	return s, nil
}

func encode(v any) []byte { return appendValue(nil, v) }

func appendSize(b []byte, n int, tiny, b8, b16, b32 byte) []byte {
	switch {
	case n < 16 && tiny != 0:
		return append(b, tiny|byte(n))
	case n < 256:
		return append(b, b8, byte(n))
	case n < 65536:
		return append(b, b16, byte(n>>8), byte(n))
	}
	return append(b, b32, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func appendValue(b []byte, v any) []byte {
	switch x := v.(type) {
	case nil:
		return append(b, 0xC0)
	case bool:
		if x {
			return append(b, 0xC3)
		}
		return append(b, 0xC2)
	case int:
		return appendInt(b, int64(x))
	case int64:
		return appendInt(b, x)
	case float64:
		b = append(b, 0xC1)
		return binary.BigEndian.AppendUint64(b, math.Float64bits(x))
	case []byte:
		b = appendSize(b, len(x), 0, 0xCC, 0xCD, 0xCE)
		return append(b, x...)
	case string:
		b = appendSize(b, len(x), 0x80, 0xD0, 0xD1, 0xD2)
		return append(b, x...)
	case []any:
		b = appendSize(b, len(x), 0x90, 0xD4, 0xD5, 0xD6)
		for _, e := range x {
			b = appendValue(b, e)
		}
		return b
	case []string:
		b = appendSize(b, len(x), 0x90, 0xD4, 0xD5, 0xD6)
		for _, e := range x {
			b = appendValue(b, e)
		}
		return b
	case map[string]any:
		b = appendSize(b, len(x), 0xA0, 0xD8, 0xD9, 0xDA)
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b = appendValue(b, k)
			b = appendValue(b, x[k])
		}
		return b
	case *Struct:
		b = append(b, 0xB0|byte(len(x.Fields)), x.Tag)
		for _, f := range x.Fields {
			b = appendValue(b, f)
		}
		return b
	}
	panic(fmt.Sprintf("packstream: cannot encode %T", v))
}

func appendInt(b []byte, x int64) []byte {
	switch {
	case x >= -16 && x < 128:
		return append(b, byte(int8(x)))
	case x >= math.MinInt8 && x <= math.MaxInt8:
		return append(b, 0xC8, byte(int8(x)))
	case x >= math.MinInt16 && x <= math.MaxInt16:
		return binary.BigEndian.AppendUint16(append(b, 0xC9), uint16(x))
	case x >= math.MinInt32 && x <= math.MaxInt32:
		return binary.BigEndian.AppendUint32(append(b, 0xCA), uint32(x))
	}
	return binary.BigEndian.AppendUint64(append(b, 0xCB), uint64(x))
}
