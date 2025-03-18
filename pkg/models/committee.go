// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

package models

import (
	"context"
	"fmt"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/database"
)

// Committee represents a committee.
type Committee struct {
	ID          int64
	Name        string
	Description *string
}

// LoadCommittees loads all committees ordered by name.
func LoadCommittees(ctx context.Context, db *database.Database) ([]*Committee, error) {
	const loadSQL = `SELECT id, name, description FROM committees ` +
		`ORDER BY name`
	rows, err := db.DB.QueryContext(ctx, loadSQL)
	if err != nil {
		return nil, fmt.Errorf("loading committees failed: %w", err)
	}
	defer rows.Close()
	var committees []*Committee
	for rows.Next() {
		var c Committee
		if err := rows.Scan(&c.ID, &c.Name, &c.Description); err != nil {
			return nil, fmt.Errorf("scanning committees failed: %w", err)
		}
		committees = append(committees, &c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loading committees failed: %w", err)
	}
	return committees, nil
}
