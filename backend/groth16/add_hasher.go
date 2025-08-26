package groth16

import (
	"github.com/consensys/gnark/frontend"
)

type Hasher struct {
	h    frontend.Variable   // current vector in the Miyaguchi–Preneel scheme
	data []frontend.Variable // state storage. data is updated when Write() is called. Sum sums the data.
	api  frontend.API        // underlying constraint system
}

// NewMiMC returns a MiMC instance, than can be used in a gnark circuit
func NewHasher(api frontend.API) (Hasher, error) {
	return Hasher{
		api:  api,
		h:    0,
		data: make([]frontend.Variable, 0),
	}, nil
}

// Write adds more data to the running hash.
func (h *Hasher) Write(data ...frontend.Variable) {
	h.data = append(h.data, data...)
}

// Reset resets the Hash to its initial state.
func (h *Hasher) Reset() {
	h.data = nil
	h.h = 0
}

func (h *Hasher) Sum() frontend.Variable {
	for _, stream := range h.data {
		h.h = h.api.Add(h.h, stream)
	}

	h.data = nil // flush the data already hashed

	return h.h
}
