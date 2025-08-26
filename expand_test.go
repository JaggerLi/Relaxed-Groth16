package gnark_test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"testing"
)

func Test_ExpandCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit groth16.ExpandCircuit

	// Initial value in SHA256
	initialState := [8]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	// Initialize message to hash
	input := []byte("One of the important properties of a good blockchain user experience is fast transaction confirmation times. Today, Ethereum has already improved a lot compared to five years ago.")
	message, _ := padding(input)
	// Generate R1CS for expandcircuit

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	_r1cs := r1cs.(*cs.R1CS)

	pk_e, pk_w, err := groth16.IVCSetup(_r1cs)
	internal, secret, public := _r1cs.GetNbVariables()
	bigInstance, err := groth16.NewCommittedRelaxedR1CS(len(_r1cs.Coefficients), internal+secret+public, public, pk_e, pk_w)
	// Make assignment
	if err != nil {
		panic(err)
	}
	comT := bigInstance.Com_E
	assignment, _, err := groth16.MakeAssignment(bigInstance, bigInstance, comT, 0, initialState[:], initialState[:], message[:64])
	if err != nil {
		panic(err)
	}
	assert.ProverSucceeded(&circuit, &groth16.ExpandCircuit{
		BigInstance:   assignment.BigInstance,
		SmallInstance: assignment.SmallInstance,
		Z0:            assignment.Z0,
		Zi:            assignment.Zi,
		Com_T:         assignment.Com_T,
		X_Out:         assignment.X_Out,
		Idx:           assignment.Idx,
		// unused field?
		U: assignment.U,
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

func padding(message []byte) ([]byte, int) {
	var num_iter int
	inputLen := len(message)
	if inputLen%64 < 56 {
		num_iter = inputLen/64 + 1
		var tmp [64]byte
		// Copy the last remaining block to tmp
		copy(tmp[:], message[inputLen/64*64:])
		// Append 0x80 to the end of the block
		tmp[inputLen%64] = 0x80
		// Put inputLen * 8 in big endian
		inputBitLen := inputLen << 3
		for i := 0; i < 8; i++ {
			tmp[63-i] = byte(inputBitLen >> (i << 3))
		}
		message = append(message, tmp[:]...)
	} else {
		num_iter = inputLen/64 + 2
		var tmp [64]byte
		// Copy the last remaining block to tmp
		copy(tmp[:], message[inputLen/64*64:])
		// Append 0x80 to the end of the block
		tmp[inputLen%64] = 0x80
		message = append(message, tmp[:]...)
		// Clear tmp
		for i := range tmp {
			tmp[i] = 0
		}
		// Put inputLen * 8 in big endian at the end of tmp
		inputBitLen := inputLen << 3
		for i := 0; i < 8; i++ {
			tmp[63-i] = byte(inputBitLen >> (i << 3))
		}
		message = append(message, tmp[:]...)
	}
	return message, num_iter
}
