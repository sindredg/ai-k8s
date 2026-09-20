package corpus

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const decisionPrefix = "Decision: "

// Anchor turns a Markdown heading into the fragment GitHub links it at.
func Anchor(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(heading)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

var tableRow = regexp.MustCompile(`^\|(.*)\|\s*$`)

// splitRow returns a Markdown table row's cells, trimmed.
func splitRow(line string) ([]string, bool) {
	m := tableRow.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	cells := strings.Split(m[1], "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	return cells, true
}

// LoadThreatModel adds one entry per numbered row of the findings table. Rows outside that table are ignored, because the boundaries table is numbered too.
func LoadThreatModel(idx *Index, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read threat model: %w", err)
	}
	defer f.Close()

	inFindings, loaded := false, 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "## ") {
			inFindings = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "## ")), "Findings")
			continue
		}
		if !inFindings {
			continue
		}

		cells, ok := splitRow(line)
		if !ok || len(cells) < 5 {
			continue
		}
		n, err := strconv.Atoi(cells[0])
		if err != nil || n < 1 {
			continue // The header and its separator, which carry no finding number.
		}

		finding, response, status := cells[2], cells[3], cells[4]
		if finding == "" || status == "" {
			return fmt.Errorf("threat model %s: finding %d has no text or no status", path, n)
		}
		e := Entry{
			ID:      ThreatID(n),
			Summary: fmt.Sprintf("%s. Proposed response: %s. Status: %s", finding, response, status),
			Source:  fmt.Sprintf("reference/threat-model.md#findings, boundary %s", cells[1]),
		}
		if err := idx.Add(e); err != nil {
			return err
		}
		loaded++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read threat model %s: %w", path, err)
	}
	if loaded == 0 {
		return fmt.Errorf("threat model %s has no findings table, or its shape changed", path)
	}
	return nil
}

// LoadDecisions adds one entry per heading carrying a Decision line. Headings without one are recorded in SkippedDecisions rather than dropped.
func LoadDecisions(idx *Index, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read decisions: %w", err)
	}
	defer f.Close()

	heading, decision := "", ""

	flush := func() error {
		if heading == "" {
			return nil
		}
		if decision == "" {
			idx.SkippedDecisions = append(idx.SkippedDecisions, heading)
			heading = ""
			return nil
		}
		e := Entry{
			ID:      DecisionID(Anchor(heading)),
			Summary: decision,
			Source:  fmt.Sprintf("decisions.md#%s, %q", Anchor(heading), heading),
		}
		heading, decision = "", ""
		return idx.Add(e)
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "### "):
			if err := flush(); err != nil {
				return err
			}
			heading = strings.TrimSpace(strings.TrimPrefix(line, "### "))
		case strings.HasPrefix(line, "## "):
			if err := flush(); err != nil {
				return err
			}
		case heading != "" && decision == "" && strings.HasPrefix(line, decisionPrefix):
			decision = strings.TrimSpace(strings.TrimPrefix(line, decisionPrefix))
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read decisions %s: %w", path, err)
	}
	if err := flush(); err != nil {
		return err
	}
	if len(idx.Entries) == 0 {
		return fmt.Errorf("decisions %s carries no Decision line, or its shape changed", path)
	}
	return nil
}
