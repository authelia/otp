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
	"encoding/base32"
	"fmt"
	"math"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/otp"
	"github.com/authelia/otp/hotp"
)

type tc struct {
	TS     int64
	TOTP   string
	Mode   otp.Algorithm
	Secret string
}

var (
	secSha1   = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	secSha256 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	secSha512 = base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	rfcMatrixTCs = []tc{
		{59, "94287082", otp.AlgorithmSHA1, secSha1},
		{59, "46119246", otp.AlgorithmSHA256, secSha256},
		{59, "90693936", otp.AlgorithmSHA512, secSha512},
		{1111111109, "07081804", otp.AlgorithmSHA1, secSha1},
		{1111111109, "68084774", otp.AlgorithmSHA256, secSha256},
		{1111111109, "25091201", otp.AlgorithmSHA512, secSha512},
		{1111111111, "14050471", otp.AlgorithmSHA1, secSha1},
		{1111111111, "67062674", otp.AlgorithmSHA256, secSha256},
		{1111111111, "99943326", otp.AlgorithmSHA512, secSha512},
		{1234567890, "89005924", otp.AlgorithmSHA1, secSha1},
		{1234567890, "91819424", otp.AlgorithmSHA256, secSha256},
		{1234567890, "93441116", otp.AlgorithmSHA512, secSha512},
		{2000000000, "69279037", otp.AlgorithmSHA1, secSha1},
		{2000000000, "90698825", otp.AlgorithmSHA256, secSha256},
		{2000000000, "38618901", otp.AlgorithmSHA512, secSha512},
		{20000000000, "65353130", otp.AlgorithmSHA1, secSha1},
		{20000000000, "77737706", otp.AlgorithmSHA256, secSha256},
		{20000000000, "47863826", otp.AlgorithmSHA512, secSha512},
	}
)

// Test vectors from http://tools.ietf.org/html/rfc6238#appendix-B
// NOTE -- the test vectors are documented as having the SAME
// secret -- this is WRONG -- they have a variable secret
// depending upon the hmac algorithm:
//
//	http://www.rfc-editor.org/errata_search.php?rfc=6238
//
// this only took a few hours of head/desk interaction to figure out.
func TestValidateRFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		valid, err := ValidateCustom(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
	}
}

func TestGenerateRFCTCs(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		passcode, err := GenerateCodeCustom(tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
			})
		assert.Nil(t, err)
		assert.Equal(t, tx.TOTP, passcode)
	}
}

func TestValidateSkew(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	tests := []tc{
		{29, "94287082", otp.AlgorithmSHA1, secSha1},
		{59, "94287082", otp.AlgorithmSHA1, secSha1},
		{61, "94287082", otp.AlgorithmSHA1, secSha1},
	}

	for _, tx := range tests {
		valid, err := ValidateCustom(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
				Skew:      1,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
	}
}

func TestGenerate(t *testing.T) {
	k, err := Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
	})
	require.NoError(t, err, "generate basic TOTP")
	require.Equal(t, "SnakeOil", k.Issuer(), "Extracting Issuer")
	require.Equal(t, "alice@example.com", k.AccountName(), "Extracting Account Name")
	require.Equal(t, 32, len(k.Secret()), "Secret is 32 bytes long as base32.")

	k, err = Generate(GenerateOpts{
		Issuer:      "Snake Oil",
		AccountName: "alice@example.com",
	})
	require.NoError(t, err, "issuer with a space in the name")
	require.Contains(t, k.String(), "issuer=Snake%20Oil")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  20,
	})
	require.NoError(t, err, "generate larger TOTP")
	require.Equal(t, 32, len(k.Secret()), "Secret is 32 bytes long as base32.")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  17, // anything that is not divisible by 5, really
	})
	require.NoError(t, err, "Secret size is valid when length not divisible by 5.")
	require.NotContains(t, k.Secret(), "=", "Secret has no escaped characters.")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		Secret:      []byte("helloworld"),
	})
	require.NoError(t, err, "Secret generation failed")
	sec, err := b32NoPadding.DecodeString(k.Secret())
	require.NoError(t, err, "Secret wa not valid base32")
	require.Equal(t, sec, []byte("helloworld"), "Specified Secret was not kept")
}

func TestGenerateIssuerQueryInjection(t *testing.T) {
	issuer := "Evil&secret=AAAAAAAAAAAAAAAA&period=60&encoder=steam"

	k, err := Generate(GenerateOpts{
		Issuer:      issuer,
		AccountName: "alice@example.com",
	})
	require.NoError(t, err)

	u, err := url.Parse(k.String())
	require.NoError(t, err)

	q := u.Query()
	require.Len(t, q["secret"], 1, "URL must contain exactly one secret")
	require.Len(t, q["period"], 1, "URL must contain exactly one period")
	require.NotContains(t, q, "encoder")
	require.Equal(t, issuer, k.Issuer())
	require.NotEqual(t, "AAAAAAAAAAAAAAAA", k.Secret())
	require.Equal(t, uint64(30), k.Period())
	require.Equal(t, otp.EncoderDefault, k.Encoder())
}

func TestGoogleLowerCaseSecret(t *testing.T) {
	w, err := otp.NewKeyFromURL(`otpauth://totp/Google%3Afoo%40example.com?secret=qlt6vmy6svfx4bt4rpmisaiyol6hihca&issuer=Google`)
	require.NoError(t, err)
	sec := w.Secret()
	require.Equal(t, "qlt6vmy6svfx4bt4rpmisaiyol6hihca", sec)

	n := time.Now().UTC()
	code, err := GenerateCode(w.Secret(), n)
	require.NoError(t, err)

	valid := Validate(code, w.Secret())
	require.True(t, valid)
}

func TestSteamSecret(t *testing.T) {
	w, err := otp.NewKeyFromURL(`otpauth://totp/username%20steam:username?secret=qlt6vmy6svfx4bt4rpmisaiyol6hihca&period=30&digits=5&issuer=username%20steam&encoder=steam`)
	require.NoError(t, err)
	require.Equal(t, "qlt6vmy6svfx4bt4rpmisaiyol6hihca", w.Secret())
	require.Equal(t, otp.EncoderSteam, w.Encoder())
	require.Equal(t, 5, w.Digits().Length())

	n := time.Now().UTC()
	opts := ValidateOpts{
		Period:  uint(w.Period()),
		Digits:  w.Digits(),
		Encoder: w.Encoder(),
	}
	code, err := GenerateCodeCustom(w.Secret(), n, opts)
	require.NoError(t, err)

	require.Len(t, code, w.Digits().Length())

	valid, err := ValidateCustom(code, w.Secret(), n, opts)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestValidateEmptySecret(t *testing.T) {
	n := time.Unix(59, 0).UTC()

	for _, secret := range []string{"", " ", "\t\n \r"} {
		t.Run(fmt.Sprintf("%q", secret), func(t *testing.T) {
			code, err := GenerateCode(secret, n)
			require.ErrorIs(t, err, otp.ErrValidateSecretEmpty)
			require.Empty(t, code)

			valid, err := ValidateCustom("824781", secret, n, ValidateOpts{
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			require.ErrorIs(t, err, otp.ErrValidateSecretEmpty)
			require.False(t, valid)

			require.False(t, Validate("824781", secret))
		})
	}
}

func TestValidateUnknownEncoder(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	n := time.Unix(59, 0).UTC()

	for _, encoder := range []otp.Encoder{"Steam", "STEAM", " steam", "bogus"} {
		t.Run(string(encoder), func(t *testing.T) {
			code, err := GenerateCodeCustom(secSha1, n, ValidateOpts{Encoder: encoder})
			require.ErrorIs(t, err, otp.ErrValidateEncoderUnknown)
			require.Empty(t, code)

			valid, err := ValidateCustom("", secSha1, n, ValidateOpts{Encoder: encoder})
			require.ErrorIs(t, err, otp.ErrValidateInputInvalidLength)
			require.False(t, valid)

			valid, err = ValidateCustom("000000", secSha1, n, ValidateOpts{Encoder: encoder})
			require.ErrorIs(t, err, otp.ErrValidateEncoderUnknown)
			require.False(t, valid)
		})
	}
}

func TestValidateMD5Unsupported(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	opts := ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmMD5, Skew: 1}

	for step := int64(0); step < 64; step++ {
		n := time.Unix(step*30, 0).UTC()

		code, err := GenerateCodeCustom(secSha1, n, opts)
		require.ErrorIs(t, err, otp.ErrValidateAlgorithmUnsupported)
		require.Empty(t, code)

		for _, passcode := range []string{"000000", "", "0000", "00000000"} {
			valid, err := ValidateCustom(passcode, secSha1, n, opts)
			require.ErrorIs(t, err, otp.ErrValidateAlgorithmUnsupported)
			require.False(t, valid)
		}
	}
}

func TestValidateSkewUnderflow(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	testCases := []struct {
		name  string
		t     time.Time
		opts  ValidateOpts
		steps []uint64
	}{
		{"ShouldNotWrapAtEpoch", time.Unix(10, 0), ValidateOpts{Skew: 1}, []uint64{math.MaxUint64}},
		{"ShouldNotWrapWithinSkew", time.Unix(40, 0), ValidateOpts{Skew: 2}, []uint64{math.MaxUint64}},
		{"ShouldNotWrapWithLargerSkew", time.Unix(10, 0), ValidateOpts{Skew: 3}, []uint64{math.MaxUint64, math.MaxUint64 - 1, math.MaxUint64 - 2}},
		{"ShouldNotWrapAfterInitialTime", time.Unix(4610, 0), ValidateOpts{Skew: 1, InitialTime: 4600}, []uint64{math.MaxUint64}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Digits = otp.DigitsSix

			for _, s := range tc.steps {
				code, err := hotp.GenerateCodeCustom(secSha1, s, hotp.ValidateOpts{Digits: otp.DigitsSix})
				require.NoError(t, err)

				valid, step, err := ValidateCustomStep(code, secSha1, tc.t, tc.opts)
				require.NoError(t, err)
				require.False(t, valid, "code for counter %d should not validate", s)
				require.Zero(t, step)
			}

			code, err := GenerateCodeCustom(secSha1, tc.t, tc.opts)
			require.NoError(t, err)

			valid, step, err := ValidateCustomStep(code, secSha1, tc.t, tc.opts)
			require.NoError(t, err)
			require.True(t, valid)
			require.Equal(t, uint64(tc.t.Unix()-int64(tc.opts.InitialTime))/30, step)
		})
	}
}

func TestValidateTimeBeforeInitialTime(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	testCases := []struct {
		name string
		t    time.Time
		opts ValidateOpts
	}{
		{"ShouldRejectBeforeEpoch", time.Unix(-1, 0), ValidateOpts{}},
		{"ShouldRejectWellBeforeEpoch", time.Unix(-1000000000, 0), ValidateOpts{}},
		{"ShouldRejectZeroTime", time.Time{}, ValidateOpts{}},
		{"ShouldRejectBeforeInitialTime", time.Unix(4599, 0), ValidateOpts{InitialTime: 4600}},
		{"ShouldRejectWellBeforeInitialTime", time.Unix(1000, 0), ValidateOpts{InitialTime: 1700000000000}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Digits = otp.DigitsSix
			tc.opts.Skew = 1

			code, err := GenerateCodeCustom(secSha1, tc.t, tc.opts)
			require.ErrorIs(t, err, otp.ErrValidateTimeBeforeInitialTime)
			require.Empty(t, code)

			valid, step, err := ValidateCustomStep("755224", secSha1, tc.t, tc.opts)
			require.ErrorIs(t, err, otp.ErrValidateTimeBeforeInitialTime)
			require.False(t, valid)
			require.Zero(t, step)
		})
	}

	for _, tc := range []struct {
		name string
		t    time.Time
		opts ValidateOpts
	}{
		{"ShouldAcceptEpoch", time.Unix(0, 0), ValidateOpts{}},
		{"ShouldAcceptInitialTime", time.Unix(4600, 0), ValidateOpts{InitialTime: 4600}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Digits = otp.DigitsSix

			code, err := GenerateCodeCustom(secSha1, tc.t, tc.opts)
			require.NoError(t, err)
			require.Equal(t, "755224", code)

			valid, step, err := ValidateCustomStep(code, secSha1, tc.t, tc.opts)
			require.NoError(t, err)
			require.True(t, valid)
			require.Zero(t, step)
		})
	}
}

func TestValidateDigitsDefault(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	n := time.Unix(59, 0).UTC()

	code, err := GenerateCodeCustom(secSha1, n, ValidateOpts{})
	require.NoError(t, err)
	require.Len(t, code, 6)

	valid, err := ValidateCustom(code, secSha1, n, ValidateOpts{})
	require.NoError(t, err)
	require.True(t, valid)

	valid, err = ValidateCustom("", secSha1, n, ValidateOpts{})
	require.ErrorIs(t, err, otp.ErrValidateInputInvalidLength)
	require.False(t, valid)
}

func TestGenerateSecretSize(t *testing.T) {
	for _, size := range []uint{1, 10, 15, 129, 1 << 20, math.MaxUint} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			k, err := Generate(GenerateOpts{
				Issuer:      "SnakeOil",
				AccountName: "alice@example.com",
				SecretSize:  size,
			})
			require.ErrorIs(t, err, otp.ErrGenerateSecretSizeInvalid)
			require.Nil(t, k)
		})
	}

	for _, size := range []uint{16, 20, 32, 128} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			k, err := Generate(GenerateOpts{
				Issuer:      "SnakeOil",
				AccountName: "alice@example.com",
				SecretSize:  size,
			})
			require.NoError(t, err)

			secret, err := b32NoPadding.DecodeString(k.Secret())
			require.NoError(t, err)
			require.Len(t, secret, int(size))
		})
	}

	k, err := Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		Secret:      []byte("helloworld"),
	})
	require.NoError(t, err)

	secret, err := b32NoPadding.DecodeString(k.Secret())
	require.NoError(t, err)
	require.Equal(t, []byte("helloworld"), secret)
}

func TestValidateAlgorithmInvalid(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	n := time.Unix(59, 0).UTC()

	for _, algorithm := range []otp.Algorithm{-1, 4, 99} {
		t.Run(fmt.Sprint(int(algorithm)), func(t *testing.T) {
			opts := ValidateOpts{Digits: otp.DigitsSix, Algorithm: algorithm, Skew: 1}

			code, err := GenerateCodeCustom(secSha1, n, opts)
			require.ErrorIs(t, err, otp.ErrValidateAlgorithmUnsupported)
			require.Empty(t, code)

			valid, err := ValidateCustom("000000", secSha1, n, opts)
			require.ErrorIs(t, err, otp.ErrValidateAlgorithmUnsupported)
			require.False(t, valid)
		})
	}
}

func TestGenerateAlgorithmUnsupported(t *testing.T) {
	for _, algorithm := range []otp.Algorithm{otp.AlgorithmMD5, -1, 4, 99} {
		t.Run(fmt.Sprint(int(algorithm)), func(t *testing.T) {
			k, err := Generate(GenerateOpts{
				Issuer:      "SnakeOil",
				AccountName: "alice@example.com",
				Algorithm:   algorithm,
			})
			require.ErrorIs(t, err, otp.ErrValidateAlgorithmUnsupported)
			require.Nil(t, k)
		})
	}
}
