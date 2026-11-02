package kb

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/v0lka/flowsh/engine"
)

func jsMapping(n *yamlNode, keys ...string) error {
	if !n.isMap() {
		return fmt.Errorf("expected a mapping")
	}
	for _, key := range n.keys {
		if !slices.Contains(keys, key) {
			return fmt.Errorf("unknown key %q", key)
		}
	}
	return nil
}

func jsScalar(n *yamlNode, key string) (string, error) {
	s, ok := n.fields[key].scalarVal()
	if !ok || s == "" {
		return "", fmt.Errorf("%s must be a nonempty scalar", key)
	}
	return s, nil
}

func jsInteger(n *yamlNode, key string) (int, error) {
	s, err := jsScalar(n, key)
	if err != nil {
		return 0, err
	}
	number, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	return number, nil
}

func decodeJSModules(n *yamlNode) ([]JSModule, error) {
	if isEmpty(n) {
		return nil, nil
	}
	if !n.isSeq() {
		return nil, fmt.Errorf("expected a sequence")
	}
	out := make([]JSModule, 0, len(n.items))
	for _, item := range n.items {
		if err := jsMapping(item, "name", "aliases", "properties", "constants", "internal"); err != nil {
			return nil, err
		}
		name, err := jsScalar(item, "name")
		if err != nil {
			return nil, err
		}
		m := JSModule{Name: name, Properties: map[string]string{}, Constants: map[string]int64{}}
		if aliases := item.fields["aliases"]; aliases != nil {
			m.Aliases, err = decodeStringList(aliases)
			if err != nil {
				return nil, err
			}
		}
		if props := item.fields["properties"]; props != nil {
			if !props.isMap() {
				return nil, fmt.Errorf("module properties must be a mapping")
			}
			for _, key := range props.keys {
				target, err := jsScalar(props, key)
				if err != nil {
					return nil, err
				}
				m.Properties[key] = target
			}
		}
		if constants := item.fields["constants"]; constants != nil {
			if !constants.isMap() {
				return nil, fmt.Errorf("module constants must be a mapping")
			}
			for _, key := range constants.keys {
				text, err := jsScalar(constants, key)
				if err != nil {
					return nil, err
				}
				value, err := strconv.ParseInt(text, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("constant %s must be an integer", key)
				}
				m.Constants[key] = value
			}
		}
		if item.fields["internal"] != nil {
			text, err := jsScalar(item, "internal")
			if err != nil {
				return nil, err
			}
			if text != "true" && text != "false" {
				return nil, fmt.Errorf("internal must be true or false")
			}
			m.Internal = text == "true"
		}
		out = append(out, m)
	}
	return out, nil
}

func decodeJSCalls(n *yamlNode) ([]JSCall, error) {
	if isEmpty(n) {
		return nil, nil
	}
	if !n.isSeq() {
		return nil, fmt.Errorf("expected a sequence")
	}
	out := make([]JSCall, 0, len(n.items))
	for i, item := range n.items {
		c, err := decodeJSCall(item)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out = append(out, c)
	}
	return out, nil
}

func decodeJSCall(n *yamlNode) (JSCall, error) {
	c := JSCall{Options: -1, ModeArg: -1, DataArg: -1, OptionShape: "record"}
	if err := jsMapping(n, "module", "export", "style", "operation", "return", "minArgs", "maxArgs", "options", "modeArg", "dataArg", "optionShape", "optionKeys", "flagOption", "flagDefault", "effects", "destructive"); err != nil {
		return c, err
	}
	for _, field := range []struct {
		key  string
		dest *string
	}{
		{"module", &c.Module}, {"export", &c.Export}, {"style", &c.Style}, {"operation", &c.Operation}, {"return", &c.Return},
	} {
		value, err := jsScalar(n, field.key)
		if err != nil {
			return c, err
		}
		*field.dest = value
	}
	for _, field := range []struct {
		key  string
		dest *int
	}{{"minArgs", &c.MinArgs}, {"maxArgs", &c.MaxArgs}, {"options", &c.Options}, {"modeArg", &c.ModeArg}, {"dataArg", &c.DataArg}} {
		if (field.key == "options" || field.key == "modeArg" || field.key == "dataArg") && n.fields[field.key] == nil {
			continue
		}
		value, err := jsInteger(n, field.key)
		if err != nil {
			return c, err
		}
		*field.dest = value
	}
	for _, field := range []struct {
		key  string
		dest *string
	}{{"optionShape", &c.OptionShape}, {"flagOption", &c.FlagOption}, {"flagDefault", &c.FlagDefault}} {
		if n.fields[field.key] == nil {
			continue
		}
		value, err := jsScalar(n, field.key)
		if err != nil {
			return c, err
		}
		*field.dest = value
	}
	if keys := n.fields["optionKeys"]; keys != nil {
		var err error
		c.OptionKeys, err = decodeStringList(keys)
		if err != nil {
			return c, err
		}
	}
	if effects := n.fields["effects"]; effects != nil {
		if !effects.isSeq() {
			return c, fmt.Errorf("effects must be a sequence")
		}
		for _, item := range effects.items {
			if err := jsMapping(item, "kind", "arg", "target"); err != nil {
				return c, err
			}
			kind, err := jsScalar(item, "kind")
			if err != nil {
				return c, err
			}
			arg, err := jsInteger(item, "arg")
			if err != nil {
				return c, err
			}
			target, err := jsScalar(item, "target")
			if err != nil {
				return c, err
			}
			c.Effects = append(c.Effects, JSEffect{Kind: engine.EffectKind(kind), Arg: arg, Target: target})
		}
	}
	if destructive := n.fields["destructive"]; destructive != nil {
		if !destructive.isSeq() {
			return c, fmt.Errorf("destructive must be a sequence")
		}
		for _, item := range destructive.items {
			if err := jsMapping(item, "option", "class", "reason"); err != nil {
				return c, err
			}
			option, err := jsScalar(item, "option")
			if err != nil {
				return c, err
			}
			class, err := jsScalar(item, "class")
			if err != nil {
				return c, err
			}
			reason, err := jsScalar(item, "reason")
			if err != nil {
				return c, err
			}
			c.Destructive = append(c.Destructive, JSDestructive{Option: option, Class: DestructiveClass(class), Reason: reason})
		}
	}
	return c, nil
}
