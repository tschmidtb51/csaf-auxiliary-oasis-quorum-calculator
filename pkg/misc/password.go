// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

package misc

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/rand/v2"
)

const alphabet = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	"0123456789"

type cryptoSource struct{}

func (cryptoSource) Uint64() uint64 {
	var cs [8]byte
	crand.Read(cs[:])
	return binary.NativeEndian.Uint64(cs[:])
}

// RandomString generates a random string of length n.
func RandomString(n int) string {
	rnd := rand.New(cryptoSource{})
	out := make([]byte, n)
	for i := range out {
		out[i] = alphabet[rnd.IntN(len(alphabet))]
	}
	return string(out)
}

// EncodePassword encodes a password to be stored in the database.
func EncodePassword(password string) string {
	raw := make([]byte, 4+sha256.Size)
	salt := raw[:4]
	crand.Read(salt)
	hash := sha256.New()
	hash.Write(salt)
	io.WriteString(hash, password)
	copy(raw[4:], hash.Sum(nil))
	return base64.URLEncoding.EncodeToString(raw)
}
