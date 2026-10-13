package rest

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// i64 is an int64 that marshals to a JSON number (exact, never float64) and
// unmarshals from either a JSON number or a quoted decimal string. This defends
// the int64 financial-identity law: account IDs (e.g. idCuenta, id) must survive
// JSON round-trips without truncation through float64 or interface{}.
//
// Backend3 (Jackson) binds Long fields from JSON numbers; emitting a number keeps
// wire compatibility while guaranteeing no precision loss for values such as
// 9007199254740993 or 9223372036854775807.
type i64 int64

func (i i64) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(i), 10)), nil
}

func (i *i64) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	s = strings.TrimSpace(s)
	if s == "" || s == "null" {
		*i = 0
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return errors.New("tupago: invalid int64 JSON: " + string(b))
	}
	*i = i64(n)
	return nil
}

var _ json.Marshaler = i64(0)
var _ json.Unmarshaler = (*i64)(nil)
