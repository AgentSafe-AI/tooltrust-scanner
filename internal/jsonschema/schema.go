package jsonschema

// Property represents a single JSON Schema property definition.
type Property struct {
	Type        string              `json:"type,omitempty"`
	Description string              `json:"description,omitempty"`
	Enum        []any               `json:"enum,omitempty"`
	Properties  map[string]Property `json:"properties,omitempty"`
	Items       *Property           `json:"items,omitempty"`
}

// Schema is a minimal JSON Schema (draft-07 compatible) used throughout ToolTrust Scanner.
type Schema struct {
	Type        string              `json:"type,omitempty"`
	Description string              `json:"description,omitempty"`
	Properties  map[string]Property `json:"properties,omitempty"`
	Required    []string            `json:"required,omitempty"`
	Items       *Property           `json:"items,omitempty"`
}

// PropertyNames returns the sorted list of property keys defined in the schema.
func (s Schema) PropertyNames() []string {
	if len(s.Properties) == 0 {
		return nil
	}
	names := make([]string, 0, len(s.Properties))
	for k := range s.Properties {
		names = append(names, k)
	}
	return names
}

// HasProperty reports whether the schema contains a property with the given name.
func (s Schema) HasProperty(name string) bool {
	_, ok := s.Properties[name]
	return ok
}
