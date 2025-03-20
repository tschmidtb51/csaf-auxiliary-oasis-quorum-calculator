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
	"strings"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/database"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/misc"
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
	Password    *string
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

// HasAnyRole checks if a membership contain any of the given roles.
func (m *Membership) HasAnyRole(roles ...Role) bool {
	return m != nil && slices.ContainsFunc(m.Roles, func(r Role) bool {
		return slices.Contains(roles, r)
	})
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

// Committees returns an iterator over the committees of the user.
func (u *User) Committees() iter.Seq[*Committee] {
	return func(yield func(*Committee) bool) {
		for _, m := range u.Memberships {
			if !yield(m.Committee) {
				return
			}
		}
	}
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
		`WHERE nickname = ?`

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
		`ON committee_roles.committees_id = committees.id ` +
		`WHERE nickname = ? ` +
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
			if err := rows.Scan(&rid, &cid, &name, &description); err != nil {
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

// Store updates user in the database.
func (u *User) Store(ctx context.Context, db *database.Database) error {
	var sets []string
	var args []any
	add := func(s string, arg any) {
		sets = append(sets, fmt.Sprintf("%s=?", s))
		args = append(args, arg)
	}
	add("firstname", u.Firstname)
	add("lastname", u.Lastname)
	if u.Password != nil {
		encoded := misc.EncodePassword(*u.Password)
		add("password", encoded)
	}
	args = append(args, u.Nickname)
	updates := strings.Join(sets, ",")
	const storeSQL = `UPDATE users SET %s WHERE nickname=?`
	sql := fmt.Sprintf(storeSQL, updates)
	if _, err := db.DB.ExecContext(ctx, sql, args...); err != nil {
		return fmt.Errorf("storing user failed: %w", err)
	}
	return nil
}

// LoadAllUsers loads all user ordered by their nickname.
func LoadAllUsers(ctx context.Context, db *database.Database) ([]*User, error) {
	var users []*User
	const loadSQL = `SELECT nickname, firstname, lastname, is_admin FROM users ` +
		`ORDER BY nickname`
	rows, err := db.DB.QueryContext(ctx, loadSQL)
	if err != nil {
		return nil, fmt.Errorf("loading users failed: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var user User
		if err := rows.Scan(
			&user.Nickname,
			&user.Firstname,
			&user.Lastname,
			&user.IsAdmin,
		); err != nil {
			return nil, fmt.Errorf("scanning users failed: %w", err)
		}
		users = append(users, &user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("loading users failed: %w", err)
	}
	return users, nil
}

// DeleteUsersByNickname deletes users by their nicknames.
func DeleteUsersByNickname(
	ctx context.Context,
	db *database.Database,
	nicknames iter.Seq[string],
) error {
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil
	}
	defer tx.Rollback()
	const deleteSQL = `DELETE FROM users WHERE nickname = ?`
	for nickname := range nicknames {
		if _, err := tx.ExecContext(ctx, deleteSQL, nickname); err != nil {
			return fmt.Errorf("deleting users failed: %w", err)
		}
	}
	return tx.Commit()
}

// StoreNew stores the user with a given password into the database.
// Returns false if the user already exists.
func (u *User) StoreNew(ctx context.Context, db *database.Database, password string) (bool, error) {
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var exists bool
	const userExistsSQL = `SELECT EXISTS(SELECT 1 FROM users WHERE nickname = ?)`
	if err := tx.QueryRowContext(ctx, userExistsSQL, u.Nickname).Scan(&exists); err != nil {
		return false, fmt.Errorf("checking user existance failed: %w", err)
	}
	encoded := misc.EncodePassword(password)
	const insertSQL = `INSERT INTO users (nickname, firstname, lastname, is_admin, password) ` +
		`VALUES (?, ?, ?, ?, ?)`
	if _, err := tx.ExecContext(
		ctx, insertSQL,
		u.Nickname, u.Firstname, u.Lastname, u.IsAdmin, encoded); err != nil {
		return false, fmt.Errorf("inserting user failed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("storing new user failed: %w", err)
	}
	return true, nil
}

// UpdateMemberships updates the memberships of the user with a given nickname.
func UpdateMemberships(
	ctx context.Context,
	db *database.Database,
	nickname string,
	memberships iter.Seq[*Membership],
) error {
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	const deleteSQL = `DELETE FROM committee_roles WHERE nickname = ?`
	if _, err := tx.ExecContext(ctx, deleteSQL, nickname); err != nil {
		return fmt.Errorf("deleting committee roles failed: %w", err)
	}
	const insertSQL = `INSERT INTO committee_roles (nickname, committees_id, committee_role_id) ` +
		`VALUES (?, ?, ?)`
	stmt, err := tx.PrepareContext(ctx, insertSQL)
	if err != nil {
		return fmt.Errorf("preparing insert into committee roles failed: %w", err)
	}
	defer stmt.Close()
	for ms := range memberships {
		for _, r := range ms.Roles {
			if _, err := stmt.ExecContext(ctx, nickname, ms.Committee.ID, r); err != nil {
				return fmt.Errorf("inserting into committee roles failed: %w", err)
			}
		}
	}
	return tx.Commit()
}
