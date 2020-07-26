package jsonmap

import (
	"bytes"
	"encoding/json"
	"fmt"

	"golang.org/x/xerrors"
)

// OrderedMap is a map that preserves its order
type OrderedMap struct {
	o []string
	m map[string]interface{}

	Marshaller func(val interface{}) (res []byte, err error)
}

// Get retrieves a value
func (m *OrderedMap) Get(key string) (val interface{}, ok bool) {
	val, ok = m.m[key]
	return
}

// Set sets the value of a key. If the key hasn't been set before its added
// as last key to the end of the map.
func (m *OrderedMap) Set(key string, val interface{}) {
	if m.m == nil {
		m.m = make(map[string]interface{})
	}
	if _, exists := m.m[key]; !exists {
		m.o = append(m.o, key)
	}

	m.m[key] = val
}

// Keys returns the list of all keys in the map
func (m *OrderedMap) Keys() []string {
	return m.o
}

// MarshalJSON marshals the map to JSON
func (m *OrderedMap) MarshalJSON() (res []byte, err error) {
	if m.Marshaller == nil {
		m.Marshaller = json.Marshal
	}

	res = append(res, '{')
	for i, key := range m.o {
		res = append(res, []byte(fmt.Sprintf("\"%s\":", key))...)

		val := m.m[key]
		if valm, ok := val.(*OrderedMap); ok {
			valm.Marshaller = m.Marshaller
		}
		b, err := m.Marshaller(val)
		if err != nil {
			return nil, err
		}
		res = append(res, b...)
		if i < len(m.o)-1 {
			res = append(res, ',')
		}
	}
	res = append(res, '}')

	return
}

// UnmarshalJSON unmarshals a JSON struct into this ordered map
func (m *OrderedMap) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	err := consumeDelimiter(dec, '{')
	if err != nil {
		return err
	}

	err = m.parseObject(dec)
	if err != nil {
		return err
	}

	return nil
}

func (m *OrderedMap) parseObject(dec *json.Decoder) error {
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return xerrors.Errorf("JSON object key must be a string")
		}

		token, err = dec.Token()
		if err != nil {
			return err
		}
		val, err := unmarshalOrderedJSON(token, dec)
		if err != nil {
			return err
		}
		m.Set(key, val)
	}

	err := consumeDelimiter(dec, '}')
	if err != nil {
		return err
	}

	return nil
}

func parseArray(dec *json.Decoder) (res []interface{}, err error) {
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, err
		}
		val, err := unmarshalOrderedJSON(token, dec)
		if err != nil {
			return nil, err
		}
		res = append(res, val)
	}

	err = consumeDelimiter(dec, ']')
	if err != nil {
		return nil, err
	}

	return res, nil
}

func unmarshalOrderedJSON(token json.Token, dec *json.Decoder) (val interface{}, err error) {
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}

	switch delim {
	case '{':
		var r OrderedMap
		err = r.parseObject(dec)
		val = &r
		return
	case '[':
		return parseArray(dec)
	default:
		return nil, xerrors.Errorf("unexpected delimiter: %q", delim)
	}
}

func consumeDelimiter(dec *json.Decoder, t json.Delim) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}

	delim, ok := token.(json.Delim)
	if !ok {
		return xerrors.Errorf("expected delimiter %q", t)
	}
	if delim != t {
		return xerrors.Errorf("expected delimiter %q, got %q", t, delim)
	}

	return nil
}

// MarshalJSON consistently marshals an OrderedMap to JSON
func MarshalJSON(om *OrderedMap, indent string, escapeHTML bool) ([]byte, error) {
	marshaller := func(val interface{}) ([]byte, error) {
		buf := bytes.NewBuffer(nil)
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(escapeHTML)
		enc.SetIndent("", indent)
		err := enc.Encode(val)
		if err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	om.Marshaller = marshaller
	return marshaller(om)
}
