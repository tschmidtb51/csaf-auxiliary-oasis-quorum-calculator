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
)

// Controller binds the endpoints to the internal logic.
type Controller struct {
	cfg   *config.Config
	db    *database.Database
	tmpls *template.Template
}

// NewController returns a new Controller.
func NewController(
	cfg *config.Config,
	db *database.Database,
) (*Controller, error) {

	path := filepath.Join(cfg.Web.Root, "templates", "*.tmpl")

	tmpls, err := template.New("index").ParseGlob(path)
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
	data := map[string]any{
		"Session": auth.SessionFromContext(r.Context()),
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "index.tmpl", data))
}

// Bind return a http handler to be used in a web server.
func (c *Controller) Bind() http.Handler {
	router := http.NewServeMux()
	mw := auth.NewMiddleware(c.cfg, c.db, "/auth")

	router.HandleFunc("/auth", c.auth)
	router.HandleFunc("/login", c.login)
	router.HandleFunc("/logout", mw.Wrap(c.logout))
	router.HandleFunc("/", mw.Wrap(c.home))

	static := http.FileServer(http.Dir(c.cfg.Web.Root))
	router.Handle("/static/", static)

	// TODO: Implement me!
	return router
}
