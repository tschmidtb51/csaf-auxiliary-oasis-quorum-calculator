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

func (c *Controller) committees(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	committees, err := models.LoadCommittees(ctx, c.db)
	if !check(w, r, err) {
		return
	}
	data := map[string]any{
		"Session":    auth.SessionFromContext(ctx),
		"User":       auth.UserFromContext(ctx),
		"Committees": committees,
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "committees.tmpl", data))
}

func (c *Controller) committeesStore(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("delete") != "" {
		committees := r.Form["committees"]
		var ids []int64
		for _, v := range committees {
			if id, err := strconv.ParseInt(v, 10, 64); err == nil {
				ids = append(ids, id)
			}
		}
		if len(ids) > 0 && !check(w, r,
			models.DeleteCommitteesByID(r.Context(), c.db, ids...)) {
			return
		}
	}
	c.committees(w, r)
}
