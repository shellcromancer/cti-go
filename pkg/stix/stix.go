package stix

import (
	"encoding/json"
)

type Bundle struct {
	Type        string            `json:"type"`
	ID          string            `json:"id"`
	SpecVersion string            `json:"spec_version"`
	Objects     []json.RawMessage `json:"objects"`
}

func (b *Bundle) FilterObjectsByType(targetType string) (objects []json.RawMessage) {
	for _, obj := range b.Objects {
		var o CommonRequired

		err := json.Unmarshal(obj, &o)
		if err != nil {
			panic(err)
		}

		if o.Type == targetType {
			objects = append(objects, obj)
		}
	}
	return objects
}

type Object json.RawMessage

func (obj Object) Type() string {
	var o CommonRequired

	err := json.Unmarshal(obj, &o)
	if err != nil {
		panic(err)
	}

	return o.Type
}
