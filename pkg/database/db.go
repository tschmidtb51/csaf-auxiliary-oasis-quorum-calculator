// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2024 Intevation GmbH <https://intevation.de>

// Package database implements the handling of the database.
package database

import (
	"context"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/config"
)

// DB implements the handling with the database connection pool.
type DB struct {
}

// NewDB creates a new connection pool.
func NewDB(ctx context.Context, cfg *config.Database) (*DB, error) {
	// TODO: Implement me!
	_ = ctx
	_ = cfg
	return &DB{}, nil
}

// Close closes the connection pool.
func (db *DB) Close(context.Context) {
	// TODO: Implement me!
}
