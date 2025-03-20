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

func (c *Controller) committeeEdit(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if !checkParam(w, r, err) {
		return
	}
	ctx := r.Context()
	committee, err := models.LoadCommittee(ctx, c.db, id)
	if !check(w, r, err) {
		return
	}
	if committee == nil {
		c.committees(w, r)
		return
	}
	data := templateData{
		"Session":   auth.SessionFromContext(ctx),
		"User":      auth.UserFromContext(ctx),
		"Committee": committee,
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "committee_edit.tmpl", data))
}

func (c *Controller) committeeEditStore(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if !checkParam(w, r, err) {
		return
	}
	ctx := r.Context()
	committee, err := models.LoadCommittee(ctx, c.db, id)
	if !check(w, r, err) {
		return
	}
	if committee == nil {
		c.committees(w, r)
		return
	}
	data := templateData{
		"Session":   auth.SessionFromContext(ctx),
		"User":      auth.UserFromContext(ctx),
		"Committee": committee,
	}
	var (
		name        = strings.TrimSpace(r.FormValue("name"))
		description = strings.TrimSpace(r.FormValue("description"))
		changed     bool
	)
	if name == "" {
		data.error("Missing committee name.")
	} else {
		if name != committee.Name {
			committee.Name = name
			changed = true
		}
		nilChanger(&changed, &committee.Description, description)
	}
	if changed && !check(w, r, committee.Store(ctx, c.db)) {
		return
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "committee_edit.tmpl", data))
}

func (c *Controller) committees(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	committees, err := models.LoadCommittees(ctx, c.db)
	if !check(w, r, err) {
		return
	}
	data := templateData{
		"Session":    auth.SessionFromContext(ctx),
		"User":       auth.UserFromContext(ctx),
		"Committees": committees,
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "committees.tmpl", data))
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
	data := templateData{
		"Session": auth.SessionFromContext(ctx),
		"User":    auth.UserFromContext(ctx),
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "committee_create.tmpl", data))
}

func (c *Controller) committeeStore(w http.ResponseWriter, r *http.Request) {
	var (
		name        = strings.TrimSpace(r.FormValue("name"))
		description = nilString(strings.TrimSpace(r.FormValue("description")))
		ctx         = r.Context()
	)
	data := templateData{
		"Name":        name,
		"Description": description,
		"Session":     auth.SessionFromContext(ctx),
		"User":        auth.UserFromContext(ctx),
	}
	if name == "" {
		data.error("Name is missing.")
	} else {
		committee, err := models.CreateCommittee(ctx, c.db, name, description)
		if !check(w, r, err) {
			return
		}
		if committee != nil {
			// Return to committee listing
			c.committees(w, r)
			return
		}
		data.error(fmt.Sprintf("Committee %q already exists.", name))
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "committee_create.tmpl", data))
}
