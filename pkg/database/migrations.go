// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

package database

import (
	"context"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/config"
)

// CheckMigrations checks if the version of the database matches
// migration level of the application.
func CheckMigrations(ctx context.Context, cfg *config.Database) (bool, error) {
	if cfg.Migrate {
		return cfg.TerminateAfterMigration, nil
	}
	// TODO: Implement me!
	_ = ctx
	return false, nil
}
