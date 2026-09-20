package corpus

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// controlsFile is controls.yaml: the controls this platform enforces, each pointing at the worklog that proved it.
type controlsFile struct {
	Controls []struct {
		Slug      string `yaml:"slug"`
		Statement string `yaml:"statement"`
		Proof     string `yaml:"proof"`
	} `yaml:"controls"`
}

// mappingFile is mapping.yaml: one Security Command Center category to zero or more pairings.
type mappingFile struct {
	Mapping map[string][]struct {
		Resource string   `yaml:"resource"`
		Cite     []string `yaml:"cite"`
		Why      string   `yaml:"why"`
	} `yaml:"mapping"`
}

// decodeStrict reads a YAML file and rejects any key the target type does not declare.
func decodeStrict(path string, into any) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

// LoadControls adds one entry per control. A control with no statement or no proof fails the build, because an unproven control is not a citable fact.
func LoadControls(idx *Index, path string) error {
	var file controlsFile
	if err := decodeStrict(path, &file); err != nil {
		return err
	}
	if len(file.Controls) == 0 {
		return fmt.Errorf("%s declares no controls", path)
	}

	for i, c := range file.Controls {
		if strings.TrimSpace(c.Slug) == "" {
			return fmt.Errorf("%s: control %d has no slug", path, i)
		}
		if strings.TrimSpace(c.Statement) == "" {
			return fmt.Errorf("%s: control %q asserts nothing", path, c.Slug)
		}
		if strings.TrimSpace(c.Proof) == "" {
			return fmt.Errorf("%s: control %q cites no proof", path, c.Slug)
		}
		e := Entry{
			ID:      ControlID(c.Slug),
			Summary: c.Statement,
			Source:  c.Proof,
		}
		if err := idx.Add(e); err != nil {
			return err
		}
	}
	return nil
}

// LoadMapping reads the hand-written category pairings. Validate resolves their citations once every source is loaded.
func LoadMapping(idx *Index, path string) error {
	var file mappingFile
	if err := decodeStrict(path, &file); err != nil {
		return err
	}
	if len(file.Mapping) == 0 {
		return fmt.Errorf("%s maps no categories", path)
	}

	for category, pairings := range file.Mapping {
		out := make([]Pairing, 0, len(pairings))
		for _, p := range pairings {
			cite := make([]ID, 0, len(p.Cite))
			for _, c := range p.Cite {
				cite = append(cite, ID(c))
			}
			out = append(out, Pairing{Resource: p.Resource, Cite: cite, Why: p.Why})
		}
		idx.Mapping[category] = out
	}
	return nil
}
