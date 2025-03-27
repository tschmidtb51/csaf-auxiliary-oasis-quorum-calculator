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
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/database"
)

// Committee represents a committee.
type Committee struct {
	ID          int64
	Name        string
	Description *string
}

// UserStatus represents a membership status.
type UserStatus struct {
	Nickname string
	Status   MemberStatus
}

type MembershipHistory struct {
	Time  time.Time
	Users []UserStatus
}

// DeleteCommitteesByID deletes a list of committees by their ids.
func DeleteCommitteesByID(ctx context.Context, db *database.Database, ids ...int64) error {
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	const deleteSQL = `DELETE FROM committees WHERE id = ?`
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, deleteSQL, id); err != nil {
			return fmt.Errorf("deleting committee failed: %w", err)
		}
	}
	return tx.Commit()
}

// GetID returns the id of this committee.
// Useful together with [misc.Map].
func (c *Committee) GetID() int64 {
	return c.ID
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

// CreateCommittee creates a new committee.
func CreateCommittee(
	ctx context.Context, db *database.Database,
	name string,
	description *string,
) (*Committee, error) {
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var exists bool
	const existsSQL = `SELECT EXISTS(SELECT 1 FROM committees WHERE name = ?)`
	if err := tx.QueryRowContext(ctx, existsSQL, name).Scan(&exists); err != nil {
		return nil, fmt.Errorf("checking committee for existance failed: %w", err)
	}
	if exists {
		return nil, nil
	}
	const insertSQL = `INSERT INTO committees (name, description) VALUES (?, ?) ` +
		`RETURNING id`
	var id int64
	if err := tx.QueryRowContext(ctx, insertSQL, name, description).Scan(&id); err != nil {
		return nil, fmt.Errorf("inserting committee failed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing committee failed: %w", err)
	}
	return &Committee{
		ID:          id,
		Name:        name,
		Description: description,
	}, nil
}

// LoadCommittee loads a committee by its id.
func LoadCommittee(ctx context.Context, db *database.Database, id int64) (*Committee, error) {
	const loadSQL = `SELECT name, description FROM committees WHERE id = ?`
	committee := Committee{ID: id}
	switch err := db.DB.QueryRowContext(ctx, loadSQL, id).Scan(
		&committee.Name,
		&committee.Description,
	); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("loading committee failed: %w", err)
	}
	return &committee, nil
}

// LoadMembershipHistory loads the membership history of the committee.
func LoadMembershipHistory(ctx context.Context, db *database.Database, id int64, limit int64) ([]*MembershipHistory, error) {
	const loadSQL = `SELECT since, GROUP_CONCAT(status || ':' || nickname) FROM member_history WHERE committees_id = ?` +
		` GROUP BY since` +
		` ORDER BY unixepoch(since) DESC LIMIT ?`
	rows, err := db.DB.QueryContext(ctx, loadSQL, id, limit)
	if err != nil {
		return nil, fmt.Errorf("loading membership history failed: %w", err)
	}
	defer rows.Close()
	var membershipHistory []*MembershipHistory
	for rows.Next() {
		var t time.Time
		var userStatusStr string

		if err := rows.Scan(&t, &userStatusStr); err != nil {
			return nil, fmt.Errorf("scanning membership history failed: %w", err)
		}
		entries := []UserStatus{}
		for _, part := range strings.Split(userStatusStr, "|") {
			var nickname string
			var status MemberStatus
			fmt.Sscanf(part, "%d:%s", &status, &nickname)
			entries = append(entries, UserStatus{
				Nickname: nickname,
				Status:   status,
			})
		}
		membershipHistory = append(membershipHistory, &MembershipHistory{
			Time:  t,
			Users: entries,
		})
	}
	return membershipHistory, nil
}

// Store stores a committee into the database.
func (c *Committee) Store(ctx context.Context, db *database.Database) error {
	const updateSQL = `UPDATE committees SET name = ?, description = ? WHERE id = ?`
	if _, err := db.DB.ExecContext(ctx, updateSQL, c.Name, c.Description, c.ID); err != nil {
		return fmt.Errorf("storing committee failed: %w", err)
	}
	return nil
}
