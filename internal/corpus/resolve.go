package corpus

// Resolve returns the entries the corpus prices this finding with. Category and resource must both
// match exactly: an accepted decision about one resource does not cover another of the same kind.
// Nothing here compares names for similarity, because name-based pairing is what produced two wrong
// matches while Phase 15 was drafted.
func (idx *Index) Resolve(category, resource string) []Entry {
	var resolved []Entry
	for _, p := range idx.Mapping[category] {
		if p.Resource != resource {
			continue
		}
		for _, id := range p.Cite {
			if e, ok := idx.Lookup(id); ok {
				resolved = append(resolved, e)
			}
		}
	}
	return resolved
}
