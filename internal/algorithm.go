package internal

import (
	"github.com/authelia/otp"
)

// IsAlgorithmSupported returns true if the algorithm can be used to generate and validate passcodes.
func IsAlgorithmSupported(algorithm otp.Algorithm) bool {
	switch algorithm {
	case otp.AlgorithmSHA1, otp.AlgorithmSHA256, otp.AlgorithmSHA512:
		return true
	default:
		return false
	}
}
