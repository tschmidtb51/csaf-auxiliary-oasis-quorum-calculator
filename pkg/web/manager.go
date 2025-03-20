// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

package web

import (
	"net/http"
	"strconv"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/auth"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/models"
)

func (c *Controller) manager(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	meetings, err := models.LoadMeetings(ctx, c.db, user.Committees())
	if !check(w, r, err) {
		return
	}
	data := templateData{
		"Session":  auth.SessionFromContext(ctx),
		"User":     user,
		"Meetings": meetings,
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "manager.tmpl", data))
}

func (c *Controller) meetingsStore(w http.ResponseWriter, r *http.Request) {
	committeeID, err := strconv.ParseInt(r.FormValue("committee"), 10, 64)
	if !check(w, r, err) {
		return
	}
	ctx := r.Context()
	if r.FormValue("delete") != "" {
		filter := func(yield func(int64) bool) {
			for _, m := range r.Form["meetings"] {
				if id, err := strconv.ParseInt(m, 10, 64); err == nil && !yield(id) {
					return
				}
			}
		}
		if !check(w, r, models.DeleteMeetingsByID(ctx, c.db, committeeID, filter)) {
			return
		}
	}
	user := auth.UserFromContext(ctx)
	remaining, err := models.LoadMeetings(ctx, c.db, user.Committees())
	if !check(w, r, err) {
		return
	}
	data := templateData{
		"Session":  auth.SessionFromContext(ctx),
		"User":     user,
		"Meetings": remaining,
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "manager.tmpl", data))
}
