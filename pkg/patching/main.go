package patching

type Operation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

type Operations []*Operation

func (o *Operations) Add(op *Operation) {
	*o = append(*o, op)
}
