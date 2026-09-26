package internal

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeQuery(t *testing.T) {
	testCases := []struct {
		name     string
		have     url.Values
		expected string
	}{
		{"ShouldReturnEmptyForNil", nil, ""},
		{"ShouldSortKeys", url.Values{"b": {"2"}, "a": {"1"}}, "a=1&b=2"},
		{"ShouldEncodeSpaceAsPercent20", url.Values{"issuer": {"Snake Oil"}}, "issuer=Snake%20Oil"},
		{"ShouldEscapeAmpersand", url.Values{"issuer": {"A&B"}}, "issuer=A%26B"},
		{"ShouldEscapePlus", url.Values{"issuer": {"A+B"}}, "issuer=A%2BB"},
		{"ShouldEscapeEquals", url.Values{"issuer": {"A=B"}}, "issuer=A%3DB"},
		{"ShouldEscapePercent", url.Values{"issuer": {"A%20B"}}, "issuer=A%2520B"},
		{"ShouldEscapeKey", url.Values{"a&b": {"1"}}, "a%26b=1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, EncodeQuery(tc.have))
		})
	}
}

func TestEncodeQueryRoundTrip(t *testing.T) {
	values := []string{
		"Snake Oil",
		"A&B",
		"A+B",
		"A=B",
		"A:B",
		"A/B",
		"A?B",
		"A#B",
		"A;B",
		"A%B",
		" leading and trailing + ",
		"Ünïcödé",
		"Evil&secret=AAAAAAAAAAAAAAAA",
	}

	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			parsed, err := url.ParseQuery(EncodeQuery(url.Values{"issuer": {value}, "secret": {"REAL"}}))
			require.NoError(t, err)
			require.Equal(t, url.Values{"issuer": {value}, "secret": {"REAL"}}, parsed)
		})
	}
}
