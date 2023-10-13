// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_SIDBytesToString(t *testing.T) {
	t.Parallel()
	testcases := map[string][]byte{
		"S-1-5-21-2127521184-1604012920-1887927527-72713": {0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0xA0, 0x65, 0xCF, 0x7E, 0x78, 0x4B, 0x9B, 0x5F, 0xE7, 0x7C, 0x87, 0x70, 0x09, 0x1C, 0x01, 0x00},
		"S-1-1-0": {0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
		"S-1-5":   {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
		"S-1-6":   func() []byte { b, err := SIDBytes(1, 6); require.NoError(t, err); return b }(),
		"S-2-22":  func() []byte { b, err := SIDBytes(2, 22); require.NoError(t, err); return b }(),
	}

	for answer, test := range testcases {
		res, err := SIDBytesToString(test)
		if err != nil {
			t.Errorf("Failed to convert %#v: %s", test, err)
		} else if answer != res {
			t.Errorf("Failed to convert %#v: %s != %s", test, res, answer)
		}
	}
}
