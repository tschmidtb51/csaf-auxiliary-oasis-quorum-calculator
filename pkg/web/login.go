// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

package web

import (
	"log/slog"
	"net/http"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/auth"
)

func check(w http.ResponseWriter, r *http.Request, err error) bool {
	if err != nil {
		slog.ErrorContext(r.Context(), "internal error", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	return true
}

func (c *Controller) auth(w http.ResponseWriter, r *http.Request) {

	// TODO: Implement me!
	data := map[string]string{
		//"error": "Login failed",
		//"nickname": `alice`,
	}
	if !check(w, r, c.tmpls.ExecuteTemplate(w, "auth.tmpl", data)) {
		return
	}
}

func (c *Controller) login(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement me!
	_ = w
	_ = r
}

func (c *Controller) logout(_ http.ResponseWriter, r *http.Request) {
	auth.SessionFromContext(r.Context()).Delete()
}
