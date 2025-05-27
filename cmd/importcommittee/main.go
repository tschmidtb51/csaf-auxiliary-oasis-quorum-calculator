// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

// Package main implements committee import.
package main

import (
	"errors"
	"fmt"
	"strings"

	"encoding/csv"
	"flag"
	"log"
	"os"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/models"
)

type user struct {
	name          string
	initialRole   models.Role
	initialStatus models.MemberStatus
}

type data struct {
	users []*user
}

func check(err error) {
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}
}

func extractUsers(records [][]string) ([]*user, error) {
	var users []*user

	if len(records) < 2 {
		return nil, errors.New("no users")
	}

	for _, row := range records[1:] {
		if len(row) < 3 {
			return nil, errors.New("not enough user infos")
		}
		status, role, name := row[0], row[1], row[2]
		status = strings.TrimSpace(status)
		role = strings.TrimSpace(role)
		name = strings.TrimSpace(name)
		// Ignore incomplete lines
		if status == "" || role == "" || name == "" {
			continue
		}
		// Parse status
		var initialStatus models.MemberStatus
		switch strings.ToLower(status) {
		case "voter":
			initialStatus = models.Voting
		case "non-voter":
			initialStatus = models.NoneVoting
		default:
			return nil, fmt.Errorf("unknown status %q for user %q", status, name)
		}
		// Parse role
		var initialRole models.Role
		switch strings.ToLower(role) {
		case "voting member":
			initialRole = models.MemberRole
		case "member":
			initialRole = models.MemberRole
			initialStatus = models.NoneVoting
		case "chair":
			initialRole = models.ChairRole
		default:
			return nil, fmt.Errorf("unknown role %q for user %q", role, name)
		}
		users = append(users, &user{
			name:          name,
			initialStatus: initialStatus,
			initialRole:   initialRole,
		})
	}

	return users, nil
}

func loadCSV(filename string) (*data, error) {

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)

	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	users, err := extractUsers(records)
	if err != nil {
		return nil, fmt.Errorf("extracting users failed: %w", err)
	}

	return &data{
		users: users,
	}, nil
}

func run(committee, csv string) error {

	table, err := loadCSV(csv)
	if err != nil {
		return fmt.Errorf("loading CSV failed: %w", err)
	}

	_ = table
	_ = committee

	return nil
}

func main() {
	var (
		committee string
		csv       string
	)
	flag.StringVar(&committee, "committee", "", "Committee to be imported")
	flag.StringVar(&csv, "csv", "committee.csv", "CSV with a committee time table to import")
	flag.Parse()
	if committee == "" {
		log.Fatalln("missing committee name")
	}
	if csv == "" {
		log.Fatalln("missing CSV filename")
	}
	check(run(committee, csv))
}
