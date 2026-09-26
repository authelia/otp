package internal

const (
	// SecretSizeMinimum is the minimum size in bytes of a generated secret, as required by RFC 4226 section 4 R6.
	SecretSizeMinimum = 16

	// SecretSizeMaximum is the maximum size in bytes of a generated secret. This is the largest HMAC block size of the
	// supported algorithms, as longer keys are hashed before use.
	SecretSizeMaximum = 128
)
