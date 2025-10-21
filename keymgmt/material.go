package keymgmt

// Material bundles a DEK with its descriptor so callers can pass them around
// as a single unit.
type Material struct {
	Key        DEK
	Descriptor Descriptor
}

// Zero overwrites the key material with zeros and leaves the descriptor intact.
func (m *Material) Zero() {
	m.Key.Zero()
}
