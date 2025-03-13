// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

// Package auth implements the authentication middleware.
package auth

import (
	"context"
	"log/slog"
	"time"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/config"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/database"
)

const cleanupInterval = 5 * time.Minute

// Cleaner removes stalled sessions from the database.
type Cleaner struct {
	cfg *config.Config
	db  *database.Database
}

// NewCleaner creates a new cleaner.
func NewCleaner(cfg *config.Config, db *database.Database) *Cleaner {
	return &Cleaner{
		cfg: cfg,
		db:  db,
	}
}

// Run removes stalled session from the database on a schedule.
func (c *Cleaner) Run(ctx context.Context) {
	c.cleanup(time.Now())
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			c.cleanup(t)
		}
	}
}

// cleanup removes stalled sessions from the database.
func (c *Cleaner) cleanup(now time.Time) {
	expired := now.Add(-c.cfg.Sessions.MaxAge)
	const deleteSQL = `DELETE FROM sessions WHERE last_access < $1`
	if _, err := c.db.DB.Exec(deleteSQL, expired); err != nil {
		slog.Error("cleaning session failed", "error", err)
	}
}
