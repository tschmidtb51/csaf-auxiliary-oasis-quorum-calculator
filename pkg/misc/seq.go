// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

package misc

import (
	"iter"
	"slices"
)

// Map returns a map iterator on a sequence.
func Map[S, T any](seq iter.Seq[S], xform func(S) T) iter.Seq[T] {
	return func(yield func(T) bool) {
		for s := range seq {
			if !yield(xform(s)) {
				return
			}
		}
	}
}

// Values returns an iterator over the variadic args.
func Values[S any](args ...S) iter.Seq[S] {
	return slices.Values(args)
}

// Filter returns a filtered by cond sequence of the given one.
func Filter[S any](seq iter.Seq[S], cond func(S) bool) iter.Seq[S] {
	return func(yield func(S) bool) {
		for s := range seq {
			if cond(s) && !yield(s) {
				return
			}
		}
	}
}
