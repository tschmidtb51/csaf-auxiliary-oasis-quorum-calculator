// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

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

func int64sFromStrings(s []string) []int64 {
	var ints []int64
	for _, v := range s {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			ints = append(ints, id)
		}
	}
	return ints
}

func (c *Controller) committeesStore(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("delete") != "" {
		committees := r.Form["committees"]
		if ids := int64sFromStrings(committees); len(ids) > 0 &&
			!check(w, r, models.DeleteCommitteesByID(r.Context(), c.db, ids...)) {
			return
		}
	}
	c.committees(w, r)
}

func (c *Controller) committeeCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data := map[string]any{
		"Session": auth.SessionFromContext(ctx),
		"User":    auth.UserFromContext(ctx),
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "committee_create.tmpl", data))
}

func nilString(s string) *string {
	if s != "" {
		return &s
	}
	return nil
}

func (c *Controller) committeeStore(w http.ResponseWriter, r *http.Request) {
	var (
		name        = strings.TrimSpace(r.FormValue("name"))
		description = nilString(strings.TrimSpace(r.FormValue("description")))
		committee   *models.Committee
		err         error
		errMsg      string
		ctx         = r.Context()
	)
	if name == "" {
		errMsg = "Name is missing."
		goto renderTemplate
	}

	committee, err = models.CreateCommittee(ctx, c.db, name, description)
	if !check(w, r, err) {
		return
	}
	if committee == nil {
		errMsg = fmt.Sprintf("Committee %q already exists.", name)
		goto renderTemplate
	}
	// Return to committee listing
	c.committees(w, r)
	return

renderTemplate:
	data := map[string]any{
		"Name":        name,
		"Description": description,
		"Session":     auth.SessionFromContext(ctx),
		"User":        auth.UserFromContext(ctx),
	}
	if errMsg != "" {
		data["Error"] = errMsg
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "committee_create.tmpl", data))
}
