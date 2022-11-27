package stream

// Recents keeps the last Events observed for duplicate detection—a bit like a
// bloom filter.
type Recents struct {
	events [2048]Event
	eventI int
	sigSet map[string]struct{}
}

// SeenRecently returns whether e was requested in any of the last preceding
// calls.
func (r *Recents) SeenRecently(e Event) bool {
	_, ok := r.sigSet[e.SigPart()]
	if ok {
		return true
	}
	// EventI points to the oldest entry; remove and replace

	if r.sigSet == nil {
		r.sigSet = make(map[string]struct{}, len(r.events))
	} else {
		delete(r.sigSet, r.events[r.eventI].SigPart())
	}
	r.sigSet[e.SigPart()] = struct{}{}

	r.events[r.eventI] = e
	r.eventI++
	r.eventI %= len(r.events)
	return false
}
