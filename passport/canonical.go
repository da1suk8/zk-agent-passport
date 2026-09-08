package passport

import (
	"bytes"
	"encoding/json"
)

// Canonicalize renders a value as JSON with object keys sorted, so that
// signatures over protocol messages do not depend on field ordering.
func Canonicalize(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	// encoding/json sorts map keys, which yields the canonical form.
	return json.Marshal(generic)
}
