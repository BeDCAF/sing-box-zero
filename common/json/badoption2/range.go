package badoption2

import (
	"encoding/json"
	"math/rand/v2"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

type Range[T int | int64 | uint32 | uint64] struct {
	From T `json:"from"`
	To   T `json:"to"`
}

func (r Range[T]) Rand() T {
	if r.To <= r.From {
		return r.From
	}
	return r.From + T(rand.Int64N(int64(r.To-r.From)+1))
}

func (r *Range[T]) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		return r.parseString(s)
	}

	var n int64
	if err := json.Unmarshal(data, &n); err == nil {
		r.From = T(n)
		r.To = T(n)
		return nil
	}

	type raw Range[T]
	var obj raw
	if err := json.Unmarshal(data, &obj); err != nil {
		return E.Cause(err, "parse Range")
	}
	*r = Range[T](obj)
	return nil
}

func (r *Range[T]) parseString(s string) error {
	if s == "" {
		return nil
	}
	sep := "-"
	if !strings.Contains(s, "-") && strings.Contains(s, ":") {
		sep = ":"
	}
	parts := strings.SplitN(s, sep, 2)
	from, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		return E.Cause(err, "parse Range from")
	}
	r.From = T(from)
	if len(parts) == 1 {
		r.To = T(from)
		return nil
	}
	to, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil {
		return E.Cause(err, "parse Range to")
	}
	r.To = T(to)
	return nil
}

func (r Range[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatInt(int64(r.From), 10) + "-" + strconv.FormatInt(int64(r.To), 10))
}
