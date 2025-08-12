/**
 *  Copyright 2014 Paul Querna
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package totp

import (
	"crypto/rand"
	"encoding/base32"
	"io"
	"net/url"
	"strconv"
	"time"

	"github.com/authelia/otp"
	"github.com/authelia/otp/hotp"
	"github.com/authelia/otp/internal"
)

// Validate a TOTP using the current time.
// A shortcut for ValidateCustom, Validate uses a configuration
// that is compatible with Google-Authenticator and most clients. See also ValidateStep.
func Validate(passcode string, secret string) (valid bool) {
	valid, _, _ = ValidateCustomStep(
		passcode,
		secret,
		time.Now().UTC(),
		ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)

	return valid
}

// ValidateStep a TOTP using the current time.
// A shortcut for ValidateCustomStep, ValidateStep uses a configuration
// that is compatible with Google-Authenticator and most clients. This function is very similar to Validate except
// Validate does not return the step. The step can be used to safely record the code used by a user to prevent replay.
func ValidateStep(passcode string, secret string) (valid bool, step uint64) {
	valid, step, _ = ValidateCustomStep(
		passcode,
		secret,
		time.Now().UTC(),
		ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)

	return valid, step
}

// GenerateCode creates a TOTP token using the current time.
// A shortcut for GenerateCodeCustom, GenerateCode uses a configuration
// that is compatible with Google-Authenticator and most clients.
func GenerateCode(secret string, t time.Time) (string, error) {
	return GenerateCodeCustom(secret, t, ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
}

// ValidateOpts provides options for ValidateCustom().
type ValidateOpts struct {
	// Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
	Period uint

	// Periods before or after the current time to allow.  Value of 1 allows up to Period
	// of either side of the specified time.  Defaults to 0 allowed skews.  Values greater
	// than 1 are likely sketchy.
	Skew uint

	// Digits as part of the input. Defaults to 6.
	Digits otp.Digits

	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm otp.Algorithm

	// Encoder to use for output code.
	Encoder otp.Encoder
}

// GenerateCodeCustom takes a timepoint and produces a passcode using a
// secret and the provided opts. (Under the hood, this is making an adapted
// call to hotp.GenerateCodeCustom)
func GenerateCodeCustom(secret string, t time.Time, opts ValidateOpts) (passcode string, err error) {
	if opts.Period == 0 {
		opts.Period = 30
	}

	counter := uint64(t.Unix()) / uint64(opts.Period)
	passcode, err = hotp.GenerateCodeCustom(secret, counter, hotp.ValidateOpts{
		Digits:    opts.Digits,
		Algorithm: opts.Algorithm,
		Encoder:   opts.Encoder,
	})
	if err != nil {
		return "", err
	}
	return passcode, nil
}

// ValidateCustom validates a TOTP given a user specified time and custom options.
// Most users should use Validate to provide an interpolatable TOTP experience.
func ValidateCustom(passcode string, secret string, t time.Time, opts ValidateOpts) (valid bool, err error) {
	valid, _, err = ValidateCustomStep(passcode, secret, t, opts)

	return valid, err
}

// ValidateCustomStep validates a TOTP given a user specified time and custom options.
// Most users should use ValidateStep to provide an interpolatable TOTP experience.
func ValidateCustomStep(passcode string, secret string, t time.Time, opts ValidateOpts) (valid bool, step uint64, err error) {
	if opts.Period == 0 {
		opts.Period = 30
	}

	steps := []uint64{uint64(t.Unix()) / uint64(opts.Period)}

	for i := uint64(1); i <= uint64(opts.Skew); i++ {
		steps = append(steps, steps[0]+i)
		steps = append(steps, steps[0]-i)
	}

	for _, currentStep := range steps {
		rv, err := hotp.ValidateCustom(passcode, currentStep, secret, hotp.ValidateOpts{
			Digits:    opts.Digits,
			Algorithm: opts.Algorithm,
			Encoder:   opts.Encoder,
		})

		if err != nil {
			return false, 0, err
		}

		if rv == true {
			return true, currentStep, nil
		}
	}

	return false, 0, nil
}

// GenerateOpts provides options for Generate().  The default values
// are compatible with Google-Authenticator.
type GenerateOpts struct {
	// Name of the issuing Organization/Company.
	Issuer string
	// Name of the User's Account (eg, email address)
	AccountName string
	// Number of seconds a TOTP hash is valid for. Defaults to 30 seconds.
	Period uint
	// Size in size of the generated Secret. Defaults to 20 bytes.
	SecretSize uint
	// Secret to store. Defaults to a randomly generated secret of SecretSize.  You should generally leave this empty.
	Secret []byte
	// Digits to request. Defaults to 6.
	Digits otp.Digits
	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm otp.Algorithm
	// Reader to use for generating TOTP Key.
	Rand io.Reader
}

var b32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Generate a new TOTP Key.
func Generate(opts GenerateOpts) (*otp.Key, error) {
	// url encode the Issuer/AccountName
	if opts.Issuer == "" {
		return nil, otp.ErrGenerateMissingIssuer
	}

	if opts.AccountName == "" {
		return nil, otp.ErrGenerateMissingAccountName
	}

	if opts.Period == 0 {
		opts.Period = 30
	}

	if opts.SecretSize == 0 {
		opts.SecretSize = 20
	}

	if opts.Digits == 0 {
		opts.Digits = otp.DigitsSix
	}

	if opts.Rand == nil {
		opts.Rand = rand.Reader
	}

	// otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

	v := url.Values{}
	if len(opts.Secret) != 0 {
		v.Set("secret", b32NoPadding.EncodeToString(opts.Secret))
	} else {
		secret := make([]byte, opts.SecretSize)
		_, err := io.ReadFull(opts.Rand, secret)
		if err != nil {
			return nil, err
		}
		v.Set("secret", b32NoPadding.EncodeToString(secret))
	}

	v.Set("issuer", opts.Issuer)
	v.Set("period", strconv.FormatUint(uint64(opts.Period), 10))
	v.Set("algorithm", opts.Algorithm.String())
	v.Set("digits", opts.Digits.String())

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + opts.Issuer + ":" + opts.AccountName,
		RawQuery: internal.EncodeQuery(v),
	}

	return otp.NewKeyFromURL(u.String())
}
