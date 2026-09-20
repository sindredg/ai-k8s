package corpus

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// checkovBaseline is the shape checkov writes with --create-baseline.
type checkovBaseline struct {
	FailedChecks []struct {
		File     string `json:"file"`
		Findings []struct {
			Resource string   `json:"resource"`
			CheckIDs []string `json:"check_ids"`
		} `json:"findings"`
	} `json:"failed_checks"`
}

// LoadCheckov adds one entry per check and resource in the baseline. Each entry is a finding this repository already accepted.
func LoadCheckov(idx *Index, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read checkov baseline: %w", err)
	}

	var baseline checkovBaseline
	if err := json.Unmarshal(raw, &baseline); err != nil {
		return fmt.Errorf("parse checkov baseline %s: %w", path, err)
	}

	for _, fc := range baseline.FailedChecks {
		if strings.TrimSpace(fc.File) == "" {
			return fmt.Errorf("checkov baseline %s has a failed_checks entry naming no file", path)
		}
		for _, f := range fc.Findings {
			if strings.TrimSpace(f.Resource) == "" {
				return fmt.Errorf("checkov baseline %s has a finding in %s naming no resource", path, fc.File)
			}
			if len(f.CheckIDs) == 0 {
				return fmt.Errorf("checkov baseline %s has a finding on %s carrying no check ids", path, f.Resource)
			}
			for _, check := range f.CheckIDs {
				if strings.TrimSpace(check) == "" {
					return fmt.Errorf("checkov baseline %s has an empty check id on %s", path, f.Resource)
				}
				e := Entry{
					ID:      CheckovID(check, f.Resource),
					Summary: fmt.Sprintf("%s is accepted against %s, recorded in the checkov baseline.", check, f.Resource),
					Source:  fmt.Sprintf(".checkov.baseline, for %s", fc.File),
				}
				if err := idx.Add(e); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
