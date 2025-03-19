// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

package web

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// shorten shortens a string to max. 40 characters.
func shorten(v any) string {
	var s string
	switch x := v.(type) {
	case *string:
		if x == nil {
			return ""
		}
		s = *x
	case string:
		s = x
	default:
		return ""
	}
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > 40 {
		runes := []rune(s)
		return string(runes[:37]) + "..."
	}
	return s
}

// int64sFromStrings converts a list of strings to int64s ignoring the bad.
func int64sFromStrings(s []string) []int64 {
	ints := make([]int64, 0, len(s))
	for _, v := range s {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			ints = append(ints, id)
		}
	}
	return ints
}

// nilString returns nil if the given string is empty else a pointer to
// the string is returned.
func nilString(s string) *string {
	if s != "" {
		return &s
	}
	return nil
}

// changer returns a function which gets
// a pointer to a potential nil string which might be changed.
// The changed pointer is used to signal a change
// to a common flag.
func changer(changed *bool) func(**string, string) {
	return func(s **string, v string) {
		switch {
		case v == "" && *s == nil:
			return
		case v != "" && *s != nil && v == **s:
			return
		case v == "" && *s != nil:
			*s = nil
		default:
			*s = &v
		}
		*changed = true
	}
}
