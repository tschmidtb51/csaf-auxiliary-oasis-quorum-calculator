// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

package auth

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/config"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/database"
)

// sessionParameter is the name of the sessionid.
const sessionParameter = "SESSIONID"

// Middleware is the middleware to handle authentication.
type Middleware struct {
	cfg      *config.Config
	db       *database.Database
	redirect string
}

type sessionKeyType int

const sessionKey sessionKeyType = 0

// NewMiddleware returns a new auth middleware.
func NewMiddleware(cfg *config.Config, db *database.Database, redirect string) *Middleware {
	return &Middleware{
		cfg:      cfg,
		db:       db,
		redirect: redirect,
	}
}

// SessionFromContext returns the session from the context.
func SessionFromContext(ctx context.Context) *Session {
	v := ctx.Value(sessionKey)
	if v == nil {
		return nil
	}
	return v.(*Session)
}

// Wrap wraps the middleware around the given next.
func (mw *Middleware) Wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.FormValue(sessionParameter)
		if sessionID == "" {
			http.Redirect(w, r, mw.redirect, http.StatusSeeOther)
			return
		}
		token, ok := mw.cfg.Sessions.CheckKey(sessionID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		var (
			user       string
			lastAccess time.Time
		)
		const userSQL = `SELECT nickname, last_access FROM sessions ` +
			`WHERE token = $1`

		switch err := mw.db.DB.QueryRowContext(r.Context(), userSQL, token).Scan(
			&user,
			&lastAccess,
		); {
		case errors.Is(err, sql.ErrNoRows):
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		case err != nil:
			slog.ErrorContext(r.Context(), "cannot load session", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if expired := time.Now().Add(-mw.cfg.Sessions.MaxAge); lastAccess.Before(expired) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		session := &Session{
			nickname: user,
			id:       sessionID,
		}
		nctx := context.WithValue(r.Context(), sessionKey, session)
		defer func() {
			var sql string
			if session.delete {
				sql = `DELETE FROM sessions WHERE token = $1`
			} else {
				sql = `UPDATE sessions SET last_access = current_timestamp ` +
					`WHERE token = $1`
			}
			if _, err := mw.db.DB.ExecContext(r.Context(), sql, token); err != nil {
				slog.ErrorContext(r.Context(),
					"updating/deleting session failed", "error", err)
			}
			if session.delete {
				http.Redirect(w, r, mw.redirect, http.StatusSeeOther)
			}
		}()
		next(w, r.WithContext(nctx))
	}
}
