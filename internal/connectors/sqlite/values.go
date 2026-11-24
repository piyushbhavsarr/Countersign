package sqlite

/*
#include <stdlib.h>
int sqlite3_complete(const char *sql);
*/
import "C"

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"unsafe"
)

// Val is one SQLite value with its storage class kept exactly: n(ull) i(nteger)
// f(loat) s(text) b(lob). It survives JSON journaling bit for bit.
type Val struct {
	K byte
	I int64
	F float64
	S string
	B []byte
}

func FromAny(v any) Val {
	switch x := v.(type) {
	case nil:
		return Val{K: 'n'}
	case int64:
		return Val{K: 'i', I: x}
	case int:
		return Val{K: 'i', I: int64(x)}
	case float64:
		return Val{K: 'f', F: x}
	case string:
		return Val{K: 's', S: x}
	case []byte:
		return Val{K: 'b', B: append([]byte{}, x...)}
	case bool:
		if x {
			return Val{K: 'i', I: 1}
		}
		return Val{K: 'i', I: 0}
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return Val{K: 'i', I: i}
		}
		f, _ := x.Float64()
		return Val{K: 'f', F: f}
	}
	return Val{K: 's', S: fmt.Sprint(v)}
}

// Any returns the value for binding into a statement.
func (v Val) Any() any {
	switch v.K {
	case 'i':
		return v.I
	case 'f':
		return v.F
	case 's':
		return v.S
	case 'b':
		if v.B == nil {
			return []byte{}
		}
		return v.B
	}
	return nil
}

func (v Val) Equal(o Val) bool {
	if v.K != o.K {
		return false
	}
	switch v.K {
	case 'i':
		return v.I == o.I
	case 'f':
		return v.F == o.F || (math.IsNaN(v.F) && math.IsNaN(o.F))
	case 's':
		return v.S == o.S
	case 'b':
		return bytes.Equal(v.B, o.B)
	}
	return true
}

func RowEqual(a, b []Val) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func (v Val) MarshalJSON() ([]byte, error) {
	switch v.K {
	case 'i':
		return []byte(`{"i":` + strconv.FormatInt(v.I, 10) + `}`), nil
	case 'f':
		if math.IsInf(v.F, 0) || math.IsNaN(v.F) {
			return json.Marshal(map[string]string{"f": strconv.FormatFloat(v.F, 'g', -1, 64)})
		}
		return []byte(`{"f":` + strconv.FormatFloat(v.F, 'g', -1, 64) + `}`), nil
	case 's':
		return json.Marshal(map[string]string{"s": v.S})
	case 'b':
		return json.Marshal(map[string]string{"b": base64.StdEncoding.EncodeToString(v.B)})
	}
	return []byte("null"), nil
}

func (v *Val) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*v = Val{K: 'n'}
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for k, raw := range m {
		switch k {
		case "i":
			i, err := strconv.ParseInt(string(raw), 10, 64)
			*v = Val{K: 'i', I: i}
			return err
		case "f":
			var s string
			if json.Unmarshal(raw, &s) == nil {
				f, err := strconv.ParseFloat(s, 64)
				*v = Val{K: 'f', F: f}
				return err
			}
			f, err := strconv.ParseFloat(string(raw), 64)
			*v = Val{K: 'f', F: f}
			return err
		case "s":
			*v = Val{K: 's'}
			return json.Unmarshal(raw, &v.S)
		case "b":
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return err
			}
			d, err := base64.StdEncoding.DecodeString(s)
			*v = Val{K: 'b', B: d}
			return err
		}
	}
	return fmt.Errorf("bad value %s", b)
}

// Display is the value as the agent sees it in previews and results.
func (v Val) Display() any {
	switch v.K {
	case 'i':
		return v.I
	case 'f':
		return v.F
	case 's':
		return v.S
	case 'b':
		return map[string]any{"$blob": base64.StdEncoding.EncodeToString(v.B)}
	}
	return nil
}

func keyString(k []Val) string { b, _ := json.Marshal(k); return string(b) }

// complete reports whether SQLite's own tokenizer considers sql a complete statement.
func complete(sql string) bool {
	cs := C.CString(sql)
	defer C.free(unsafe.Pointer(cs))
	return C.sqlite3_complete(cs) != 0
}

// SplitStatements splits a script exactly where SQLite says a statement ends.
func SplitStatements(sql string) []string {
	var out []string
	start := 0
	for i := 0; i < len(sql); i++ {
		if sql[i] == ';' && complete(sql[start:i+1]) {
			if s := trim(sql[start : i+1]); s != "" && s != ";" {
				out = append(out, s)
			}
			start = i + 1
		}
	}
	if s := trim(sql[start:]); s != "" {
		out = append(out, s)
	}
	return out
}

func trim(s string) string { return string(bytes.TrimSpace([]byte(s))) }
