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
	"net/http"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/auth"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/config"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/database"
)

// Controller binds the endpoints to the internal logic.
type Controller struct {
	cfg *config.Config
	db  *database.Database
}

// NewController returns a new Controller.
func NewController(
	cfg *config.Config,
	db *database.Database,
) *Controller {
	return &Controller{
		cfg: cfg,
		db:  db,
	}
}

func (c *Controller) home(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement me!
}

func (c *Controller) auth(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement me!
}

func (c *Controller) login(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement me!
}

func (c *Controller) logout(w http.ResponseWriter, r *http.Request) {
	auth.SessionFromContext(r.Context()).Delete()
}

// Bind return a http handler to be used in a web server.
func (c *Controller) Bind() http.Handler {
	router := http.NewServeMux()
	mw := auth.NewMiddleware(c.cfg, c.db, "/auth")

	router.HandleFunc("/auth", c.auth)
	router.HandleFunc("/login", c.login)
	router.HandleFunc("/logout", mw.Wrap(c.logout))
	router.HandleFunc("/", mw.Wrap(c.home))

	// TODO: Implement me!
	return router
}
