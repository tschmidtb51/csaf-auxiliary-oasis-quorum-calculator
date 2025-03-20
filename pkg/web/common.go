// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

package web

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// datetimeHoursMinutes rounds the duration to minutes
// and returns a value suitable for datetime attributes.
func datetimeHoursMinutes(d time.Duration) string {
	d = d.Round(time.Minute)
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	return fmt.Sprintf("PT%dH%dM", hours, minutes)
}

// hoursMinutes rounds the duration to minutes
// and returns a human form.
func hoursMinutes(d time.Duration) string {
	d = d.Round(time.Minute)
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	var b strings.Builder
	b.WriteString(strconv.Itoa(hours))
	b.WriteByte('h')
	if minutes != 0 {
		b.WriteByte(' ')
		b.WriteString(strconv.Itoa(minutes))
		b.WriteByte('m')
	}
	return b.String()
}

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

// nilChanger updates a potential nil string.
func nilChanger(changed *bool, s **string, v string) {
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

// args is used in templates to construct maps of key/value pairs.
func args(args ...any) (any, error) {
	n := len(args)
	if n%2 == 1 {
		return nil, errors.New("number of args have to be even")
	}
	m := make(map[any]any, n/2)
	for i := 0; i < n; i += 2 {
		key, value := args[i], args[i+1]
		m[key] = value
	}
	return m, nil
}
