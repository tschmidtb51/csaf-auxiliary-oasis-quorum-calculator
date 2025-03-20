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
	"fmt"
	"iter"
	"slices"
	"time"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/database"
)

// Meeting holds the informations about a meeting.
type Meeting struct {
	ID          int64
	CommitteeID int64
	Running     bool
	StartTime   time.Time
	StopTime    time.Time
	Description *string
}

// Meetings is a slice of meetings.
type Meetings []*Meeting

// CommitteeIDFilter creates a filter condition which looks for
// meetings with the given committee id.
func CommitteeIDFilter(id int64) func(m *Meeting) bool {
	return func(m *Meeting) bool {
		return m.CommitteeID == id
	}
}

// Duration returns duration of the meeting.
func (m *Meeting) Duration() time.Duration {
	return m.StopTime.Sub(m.StartTime)
}

// Filter returns a sequence of meetings which fulfill the given condition.
func (ms Meetings) Filter(cond func(m *Meeting) bool) iter.Seq[*Meeting] {
	return func(yield func(m *Meeting) bool) {
		for _, m := range ms {
			if cond(m) && !yield(m) {
				return
			}
		}
	}
}

// Contains checks if there is a meeting fulfilling the given condition.
func (ms Meetings) Contains(cond func(m *Meeting) bool) bool {
	return slices.ContainsFunc(ms, cond)
}

// LoadMeetings loads meetings for a sequence of committees.
func LoadMeetings(
	ctx context.Context,
	db *database.Database,
	committees iter.Seq[*Committee],
) (Meetings, error) {
	tx, err := db.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	const loadSQL = `SELECT id, running, start_time, stop_time, description ` +
		`FROM meetings ` +
		`WHERE committees_id = ? `
	stmt, err := tx.PrepareContext(ctx, loadSQL)
	if err != nil {
		return nil, fmt.Errorf("preparing loadind meetings failed: %w", err)
	}
	defer stmt.Close()
	var meetings Meetings
	for committee := range committees {
		rows, err := stmt.QueryContext(ctx, committee.ID)
		if err != nil {
			return nil, fmt.Errorf("querying meetings failed: %w", err)
		}
		if err := func() error {
			defer rows.Close()
			for rows.Next() {
				meeting := Meeting{CommitteeID: committee.ID}
				if err := rows.Scan(
					&meeting.ID,
					&meeting.Running,
					&meeting.StartTime,
					&meeting.StopTime,
					&meeting.Description,
				); err != nil {
					return nil
				}
				meetings = append(meetings, &meeting)
			}
			return rows.Err()
		}(); err != nil {
			return nil, fmt.Errorf("scanning meetings failed: %w", err)
		}
	}
	slices.SortFunc(meetings, func(a, b *Meeting) int {
		return a.StartTime.Compare(b.StartTime)
	})
	return meetings, nil
}

func DeleteMeetingsByID(
	ctx context.Context,
	db *database.Database,
	committeeID int64,
	meetingsIDs iter.Seq[int64],
) error {
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	const deleteSQL = `DELETE FROM meetings WHERE id = ? AND committees_id = ?`
	stmt, err := tx.PrepareContext(ctx, deleteSQL)
	if err != nil {
		return fmt.Errorf("preparing delete meetings failed: %w", err)
	}
	defer stmt.Close()
	for meetingID := range meetingsIDs {
		if _, err := stmt.ExecContext(ctx, meetingID, committeeID); err != nil {
			return fmt.Errorf("deleting meeting failed: %w", err)
		}
	}
	return tx.Commit()
}
