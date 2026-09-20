// Command corpusc compiles the corpus into one index at image build time.
//
// The worker reads the index and never reads a corpus source, so nothing it cites can change
// under it at runtime and no egress to GitHub is opened. A malformed entry, an id collision, a
// mapping citing an id that does not exist, or a mapping without its justification fails here,
// which fails the build rather than the worker.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sindredg/ai-k8s/internal/corpus"
)

func main() {
	klab := flag.String("k8-lab", "", "path to a k8-lab checkout, holding the first three sources")
	agent := flag.String("corpus", "corpus", "directory holding the agent's own controls.yaml and mapping.yaml")
	out := flag.String("out", "corpus.json", "where to write the compiled index")
	flag.Parse()

	if *klab == "" {
		fail("-k8-lab is required: the checkov baseline, the threat model and decisions.md live there")
	}

	sources := corpus.Sources{
		CheckovBaseline: filepath.Join(*klab, ".checkov.baseline"),
		ThreatModel:     filepath.Join(*klab, "reference", "threat-model.md"),
		Decisions:       filepath.Join(*klab, "decisions.md"),
		Controls:        filepath.Join(*agent, "controls.yaml"),
		Mapping:         filepath.Join(*agent, "mapping.yaml"),
	}

	index, err := corpus.Compile(sources)
	if err != nil {
		fail("%v", err)
	}

	body, err := index.Marshal()
	if err != nil {
		fail("encode the index: %v", err)
	}
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		fail("write %s: %v", *out, err)
	}

	fmt.Print(index.Report())
	fmt.Printf("wrote %s\n", *out)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "corpusc: "+format+"\n", args...)
	os.Exit(1)
}
