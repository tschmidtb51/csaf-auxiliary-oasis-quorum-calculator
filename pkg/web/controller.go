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
	"strings"
	"unicode/utf8"

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

func shorten(s string) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > 40 {
		runes := []rune(s)
		return string(runes[:37]) + "..."
	}
	return s
}

// templateFuncs are the functions usable in the templates.
var templateFuncs = template.FuncMap{
	"Role":    models.ParseRole,
	"Shorten": shorten,
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
	data := map[string]any{
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

	router.HandleFunc("/committees", mw.Admin(c.committees))
	router.HandleFunc("/committees_store", mw.Admin(c.committeesStore))

	static := http.FileServer(http.Dir(c.cfg.Web.Root))
	router.Handle("/static/", static)

	// TODO: Implement me!
	return router
}
