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
	"log/slog"
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

// templateFuncs are the functions usable in the templates.
var templateFuncs = template.FuncMap{
	"Role":              models.ParseRole,
	"Shorten":           shorten,
	"Args":              args,
	"CommitteeIDFilter": models.CommitteeIDFilter,
	"HoursMinutes":      hoursMinutes,
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

func checkParam(w http.ResponseWriter, err error) bool {
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func check(w http.ResponseWriter, r *http.Request, err error) bool {
	if err != nil {
		slog.ErrorContext(r.Context(), "internal error", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	return true
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

	router.HandleFunc("/auth", c.auth)
	router.HandleFunc("/login", c.login)
	router.HandleFunc("/logout", mw.LoggedIn(c.logout))
	router.HandleFunc("/", mw.User(c.home))

	router.HandleFunc("/user", mw.User(c.user))
	router.HandleFunc("/user_store", mw.User(c.userStore))
	router.HandleFunc("/user_create", mw.Admin(c.userCreate))
	router.HandleFunc("/user_edit", mw.Admin(c.userEdit))
	router.HandleFunc("/user_edit_store", mw.Admin(c.userEditStore))
	router.HandleFunc("/user_create_store", mw.Admin(c.userCreateStore))
	router.HandleFunc("/user_committees_store", mw.Admin(c.userCommitteesStore))
	router.HandleFunc("/users", mw.Admin(c.users))
	router.HandleFunc("/users_store", mw.Admin(c.usersStore))

	router.HandleFunc("/committee_edit", mw.Admin(c.committeeEdit))
	router.HandleFunc("/committee_edit_store", mw.Admin(c.committeeEditStore))
	router.HandleFunc("/committees", mw.Admin(c.committees))
	router.HandleFunc("/committees_store", mw.Admin(c.committeesStore))
	router.HandleFunc("/committee_create", mw.Admin(c.committeeCreate))
	router.HandleFunc("/committee_store", mw.Admin(c.committeeStore))

	router.HandleFunc("/manager", mw.Roles(c.manager, models.ManagerRole))

	router.HandleFunc("/meetings_store", mw.Roles(c.meetingsStore, models.ManagerRole))

	static := http.FileServer(http.Dir(c.cfg.Web.Root))
	router.Handle("/static/", static)

	// TODO: Implement me!
	return router
}
