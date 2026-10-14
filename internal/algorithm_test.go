package internal

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/authelia/otp"
)

func TestIsAlgorithmSupported(t *testing.T) {
	testCases := []struct {
		have     otp.Algorithm
		expected bool
	}{
		{otp.AlgorithmSHA1, true},
		{otp.AlgorithmSHA256, true},
		{otp.AlgorithmSHA512, true},
		{otp.AlgorithmMD5, false},
		{otp.Algorithm(-1), false},
		{otp.Algorithm(4), false},
		{otp.Algorithm(99), false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprint(int(tc.have)), func(t *testing.T) {
			require.Equal(t, tc.expected, IsAlgorithmSupported(tc.have))
		})
	}
}
