// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

package database

import (
	"bytes"
	"cmp"
	"context"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/config"
	"github.com/jmoiron/sqlx"
)

//go:embed migrations
var migrations embed.FS

// migration stores the meta information extracted from the
// embedded SQL migration files and their names.
type migration struct {
	version     int64
	description string
	path        string
}

func needsCreation(url string) (bool, error) {
	idx := strings.IndexRune(url, '?')
	if idx != -1 {
		url = url[:idx]
	}
	switch _, err := os.Stat(url); {
	case errors.Is(err, os.ErrNotExist):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("unable to examine database %q: %w", url, err)
	}
	return false, nil
}

func sqlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

var funcs = template.FuncMap{
	"sqlQuote": sqlQuote,
}

func (m *migration) load(cfg *config.Database) (string, error) {
	data, err := migrations.ReadFile(m.path)
	if err != nil {
		return "", fmt.Errorf("loading migration %q failed: %w", m.path, err)
	}
	tmpl, err := template.New("sql").Funcs(funcs).Parse(string(data))
	if err != nil {
		return "", fmt.Errorf("parsing migration %q failed: %w", m.path, err)
	}
	var script bytes.Buffer
	if err := tmpl.Execute(&script, cfg); err != nil {
		return "", fmt.Errorf("templating migration %q failed: %w", m.path, err)
	}
	return script.String(), nil
}

func createDatabase(ctx context.Context, cfg *config.Database, db *sqlx.DB, migs []migration) error {
	script, err := migs[0].load(cfg)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, script); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO versions (version, description) VALUES ($1, $2)",
		migs[len(migs)-1].version,
		migs[len(migs)-1].description,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func listMigrations() ([]migration, error) {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	migReg, err := regexp.Compile(`^(\d+)-([^.]+)\.sql$`)
	if err != nil {
		return nil, err
	}
	var migs []migration
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		m := migReg.FindStringSubmatch(filepath.Base(entry.Name()))
		if m == nil {
			continue
		}
		version, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return nil, err
		}
		description := m[2]
		path := "migrations/" + entry.Name()
		migs = append(migs, migration{
			version:     version,
			description: description,
			path:        path,
		})
	}
	slices.SortFunc(migs, func(a, b migration) int {
		return cmp.Compare(a.version, b.version)
	})
	return migs, nil
}
