// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

// Package web implements the endpoints of the web server.
package web

import (
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/auth"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/config"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/database"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/models"
)

// Controller binds the endpoints to the internal logic.
type Controller struct {
	cfg   *config.Config
	db    *database.Database
	tmpls *template.Template
}

type templateData map[string]any

func (td templateData) error(msg string) {
	td["Error"] = msg
}

func (td templateData) hasError() bool {
	_, ok := td["Error"]
	return ok
}

// templateFuncs are the functions usable in the templates.
var templateFuncs = template.FuncMap{
	"Role":                 models.ParseRole,
	"Shorten":              shorten,
	"Args":                 args,
	"CommitteeIDFilter":    models.CommitteeIDFilter,
	"DatetimeHoursMinutes": datetimeHoursMinutes,
	"HoursMinutes":         hoursMinutes,
}

// NewController returns a new Controller.
func NewController(
	cfg *config.Config,
	db *database.Database,
) (*Controller, error) {

	path := filepath.Join(cfg.Web.Root, "templates", "*.tmpl")

	tmpls, err := template.New("index").Funcs(templateFuncs).ParseGlob(path)
	if err != nil {
		return nil, fmt.Errorf("loading templates failed: %w", err)
	}

	return &Controller{
		cfg:   cfg,
		db:    db,
		tmpls: tmpls,
	}, nil
}

func (c *Controller) home(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement me!
	ctx := r.Context()
	data := templateData{
		"Session": auth.SessionFromContext(ctx),
		"User":    auth.UserFromContext(ctx),
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "index.tmpl", data))
}

// Bind return a http handler to be used in a web server.
func (c *Controller) Bind() http.Handler {
	router := http.NewServeMux()
	mw := auth.NewMiddleware(c.cfg, c.db, "/auth")

	for _, route := range []struct {
		pattern string
		handler http.HandlerFunc
	}{
		// Auth
		{"/auth", c.auth},
		{"/login", c.login},
		{"/logout", mw.LoggedIn(c.logout)},
		{"/", mw.User(c.home)},
		// User
		{"/user", mw.User(c.user)},
		{"/user_store", mw.User(c.userStore)},
		{"/user_create", mw.Admin(c.userCreate)},
		{"/user_edit", mw.Admin(c.userEdit)},
		{"/user_edit_store", mw.Admin(c.userEditStore)},
		{"/user_create_store", mw.Admin(c.userCreateStore)},
		{"/user_committees_store", mw.Admin(c.userCommitteesStore)},
		{"/users", mw.Admin(c.users)},
		{"/users_store", mw.Admin(c.usersStore)},
		// Committees
		{"/committee_edit", mw.Admin(c.committeeEdit)},
		{"/committee_edit_store", mw.Admin(c.committeeEditStore)},
		{"/committees", mw.Admin(c.committees)},
		{"/committees_store", mw.Admin(c.committeesStore)},
		{"/committee_create", mw.Admin(c.committeeCreate)},
		{"/committee_store", mw.Admin(c.committeeStore)},
		// Chair
		{"/chair", mw.Roles(c.chair, models.ChairRole)},
		{"/meetings_store", mw.Roles(c.meetingsStore, models.ChairRole)},
		{"/meeting_create", mw.Roles(c.meetingCreate, models.ChairRole)},
		{"/meeting_create_store", mw.Roles(c.meetingCreateStore, models.ChairRole)},
		{"/meeting_edit", mw.Roles(c.meetingEdit, models.ChairRole)},
		{"/meeting_edit_store", mw.Roles(c.meetingEditStore, models.ChairRole)},
	} {
		router.HandleFunc(route.pattern, route.handler)
	}

	static := http.FileServer(http.Dir(c.cfg.Web.Root))
	router.Handle("/static/", static)

	// TODO: Implement me!
	return router
}
