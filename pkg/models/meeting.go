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
	"iter"
	"slices"
	"time"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/database"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/misc"
)

// MeetingStatus represents the current status of a meeting.
type MeetingStatus int

const (
	// MeetingOnHold represents a meeting that is currently not running.
	MeetingOnHold MeetingStatus = iota
	// MeetingRunning represents a meeting that is currently running.
	MeetingRunning
	// MeetingConcluded represents a finished meeting.
	MeetingConcluded
)

// Meeting holds the informations about a meeting.
type Meeting struct {
	ID          int64
	CommitteeID int64
	Status      MeetingStatus
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

// OverlapFilter creates a filter which checks if a meeting overlaps
// a given interval.
func OverlapFilter(start, stop time.Time, exceptions ...int64) func(m *Meeting) bool {
	return func(m *Meeting) bool {
		return !(m.StopTime.Before(start) || stop.Before(m.StartTime)) &&
			!slices.Contains(exceptions, m.ID)
	}
}

// Duration returns duration of the meeting.
func (m *Meeting) Duration() time.Duration {
	return m.StopTime.Sub(m.StartTime)
}

// Filter returns a sequence of meetings which fulfill the given condition.
func (ms Meetings) Filter(cond func(m *Meeting) bool) iter.Seq[*Meeting] {
	return misc.Filter(slices.Values(ms), cond)
}

// Contains checks if there is a meeting fulfilling the given condition.
func (ms Meetings) Contains(cond func(m *Meeting) bool) bool {
	return slices.ContainsFunc(ms, cond)
}

// LoadMeeting loads a meeting by its id.
func LoadMeeting(
	ctx context.Context, db *database.Database,
	meetingID, committeeID int64,
) (*Meeting, error) {
	meeting := Meeting{
		ID:          meetingID,
		CommitteeID: committeeID,
	}
	const loadSQL = `SELECT status, start_time, stop_time, description ` +
		`FROM meetings ` +
		`WHERE id = ? AND committees_id = ?`
	switch err := db.DB.QueryRowContext(ctx, loadSQL, meetingID, committeeID).Scan(
		&meeting.Status,
		&meeting.StartTime,
		&meeting.StopTime,
		&meeting.Description,
	); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("loading meeting failed: %w", err)
	}
	return &meeting, nil
}

// LoadMeetings loads meetings for a sequence of committees.
func LoadMeetings(
	ctx context.Context,
	db *database.Database,
	committees iter.Seq[int64],
) (Meetings, error) {
	tx, err := db.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	const loadSQL = `SELECT id, status, start_time, stop_time, description ` +
		`FROM meetings ` +
		`WHERE committees_id = ? `
	stmt, err := tx.PrepareContext(ctx, loadSQL)
	if err != nil {
		return nil, fmt.Errorf("preparing loadind meetings failed: %w", err)
	}
	defer stmt.Close()
	var meetings Meetings
	for committee := range committees {
		rows, err := stmt.QueryContext(ctx, committee)
		if err != nil {
			return nil, fmt.Errorf("querying meetings failed: %w", err)
		}
		if err := func() error {
			defer rows.Close()
			for rows.Next() {
				meeting := Meeting{CommitteeID: committee}
				if err := rows.Scan(
					&meeting.ID,
					&meeting.Status,
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

// DeleteMeetingsByID removes meetings the database identified by their id.
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

// StoreNew stores a new meeting into the database.
func (m *Meeting) StoreNew(ctx context.Context, db *database.Database) error {
	const insertSQL = `INSERT INTO meetings ` +
		`(committees_id, start_time, stop_time, description) ` +
		`VALUES (?, ?, ?, ?) ` +
		`RETURNING id`
	if err := db.DB.QueryRowContext(ctx, insertSQL,
		m.CommitteeID,
		m.StartTime,
		m.StopTime,
		m.Description,
	).Scan(&m.ID); err != nil {
		return fmt.Errorf("inserting meeting into database failed: %w", err)
	}
	return nil
}

// Store updates a meeting in the database.
func (m *Meeting) Store(ctx context.Context, db *database.Database) error {
	const updateSQL = `UPDATE meetings SET ` +
		`start_time = ?,` +
		`stop_time = ?,` +
		`description = ? ` +
		`WHERE id = ? AND committees_id = ?`
	if _, err := db.DB.ExecContext(ctx, updateSQL,
		m.StartTime,
		m.StopTime,
		m.Description,
		m.ID, m.CommitteeID); err != nil {
		return fmt.Errorf("updating meeting failed: %w", err)
	}
	return nil
}
