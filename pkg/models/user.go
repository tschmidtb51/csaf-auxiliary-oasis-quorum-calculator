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
	"slices"
	"strings"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/database"
)

// Role is the role in the committee.
type Role int

const (
	// ManagerRole is the manager role.
	ManagerRole Role = iota
	// MemberRole is the member role.
	MemberRole
)

// ParseRole parses a role from a string.
func ParseRole(s string) (Role, error) {
	switch strings.ToLower(s) {
	case "manager":
		return ManagerRole, nil
	case "member":
		return MemberRole, nil
	default:
		return 0, fmt.Errorf("invalid role %q", s)
	}
}

// String implements [fmt.Stringer].
func (r Role) String() string {
	switch r {
	case ManagerRole:
		return "manager"
	case MemberRole:
		return "member"
	default:
		return "unknown role"
	}
}

// Committee represents a committee.
type Committee struct {
	ID          int64
	Name        string
	Description *string
}

// Membership is the membership of a user in a committee.
type Membership struct {
	Committee *Committee
	Roles     []Role
}

// User is the from the database.
type User struct {
	Nickname    string
	Firstname   *string
	Lastname    *string
	IsAdmin     bool
	Memberships []*Membership
	password    *string
}

// IsMember returns true if user is member of a committee with a given name.
func (u *User) IsMember(committeeName string) bool {
	return u.FindMembership(committeeName) != nil
}

// FindMembership looks up a membership of a user by name.
func (u *User) FindMembership(committeeName string) *Membership {
	if idx := slices.IndexFunc(u.Memberships, func(m *Membership) bool {
		return m.Committee.Name == committeeName
	}); idx != -1 {
		return u.Memberships[idx]
	}
	return nil
}

// HasRole checks if a membership contains a certain role.
func (m *Membership) HasRole(role Role) bool {
	return m != nil && slices.Contains(m.Roles, role)
}

// CountMemberships count the memberships with a given role.
func (u *User) CountMemberships(role Role) int {
	count := 0
	for _, m := range u.Memberships {
		if m.HasRole(role) {
			count++
		}
	}
	return count
}

// SetPassword sets the password of the user.
func (u *User) SetPassword(password string) {
	if u.password == nil || *u.password != password {
		u.password = &password
	}
}

// PasswordChanged returns true if the password has changed.
func (u *User) PasswordChanged() bool {
	return u.password != nil
}

// LoadUser loads a user with a given nickname from the database.
func LoadUser(ctx context.Context, db *database.Database, nickname string) (*User, error) {

	tx, err := db.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Collect user details
	user := User{Nickname: nickname}
	const userSQL = `SELECT firstname, lastname, is_admin ` +
		`FROM users ` +
		`WHERE nickname = $1`

	switch err := tx.QueryRowContext(ctx, userSQL, nickname).Scan(
		&user.Firstname,
		&user.Lastname,
		&user.IsAdmin,
	); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, err
	}

	// Collect memberships
	const committeeRolesSQL = `SELECT committee_role_id, committees_id, name, description ` +
		`FROM committee_roles JOIN committees ` +
		`ON committee_roles.committee_role_id = committees.id ` +
		`WHERE nickname = $1 ` +
		`ORDER BY committees_id, committee_role_id`

	rows, err := tx.QueryContext(ctx, committeeRolesSQL, nickname)
	if err != nil {
		return nil, err
	}
	if err := func() error {
		defer rows.Close()
		for rows.Next() {
			var (
				cid         int64
				rid         int
				name        string
				description *string
			)
			if err := rows.Scan(&cid, &rid, &name, &description); err != nil {
				return err
			}
			if n := len(user.Memberships); n == 0 || user.Memberships[n-1].Committee.ID != cid {
				user.Memberships = append(user.Memberships, &Membership{
					Committee: &Committee{
						ID:          cid,
						Name:        name,
						Description: description,
					},
				})
			}
			ms := user.Memberships[len(user.Memberships)-1]
			ms.Roles = append(ms.Roles, Role(rid))
		}
		return rows.Err()
	}(); err != nil {
		return nil, err
	}

	return &user, nil
}
