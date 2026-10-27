package server

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// EditKeys edits the keys list of the config file at path, keeping comments and the rest
// of the file intact. fn receives the YAML sequence node of keys. The result is validated
// before it is written. A missing file is created.
func EditKeys(path string, fn func(keys *yaml.Node) error) error {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var doc yaml.Node
	if len(bytes.TrimSpace(data)) > 0 {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: top level must be a mapping", path)
	}
	var keys *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "keys" {
			keys = root.Content[i+1]
		}
	}
	if keys == nil || keys.Tag == "!!null" {
		if keys == nil {
			keys = &yaml.Node{}
			root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "keys"}, keys)
		}
		*keys = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	}
	if keys.Kind != yaml.SequenceNode {
		return fmt.Errorf("%s: keys must be a list", path)
	}
	keys.Style = 0 // block style, even if it was written as []
	if err := fn(keys); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	enc.Close()
	if _, err := ParseConfig(buf.Bytes()); err != nil {
		return fmt.Errorf("refusing to write invalid config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, buf.Bytes(), 0o600, nil)
}

// KeyNode encodes a key for insertion with EditKeys.
func KeyNode(k *Key) (*yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(k); err != nil {
		return nil, err
	}
	return &n, nil
}

// KeyIndex returns the position of the key named name in a keys sequence node, or -1.
func KeyIndex(keys *yaml.Node, name string) int {
	for i, item := range keys.Content {
		for j := 0; j+1 < len(item.Content); j += 2 {
			if item.Content[j].Value == "name" && item.Content[j+1].Value == name {
				return i
			}
		}
	}
	return -1
}

// SetKeyField sets a scalar field of a key mapping node, adding it if missing.
func SetKeyField(item *yaml.Node, field, value string) {
	for j := 0; j+1 < len(item.Content); j += 2 {
		if item.Content[j].Value == field {
			item.Content[j+1] = &yaml.Node{Kind: yaml.ScalarNode, Value: value}
			return
		}
	}
	item.Content = append(item.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: field},
		&yaml.Node{Kind: yaml.ScalarNode, Value: value})
}
