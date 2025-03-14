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

// SessionParameter is the name of the sessionid.
const SessionParameter = "SESSIONID"

// Middleware is the middleware to handle authentication.
type Middleware struct {
	cfg      *config.Config
	db       *database.Database
	redirect string
}

type sessionKeyType int

const sessionKey sessionKeyType = 0

// Session encapsulte a database session.
type Session struct {
	delete bool
	user   string
}

// NewMiddleware returns a new auth middleware.
func NewMiddleware(cfg *config.Config, db *database.Database, redirect string) *Middleware {
	return &Middleware{
		cfg:      cfg,
		db:       db,
		redirect: redirect,
	}
}

// User returns the user connected with the session.
func (s *Session) User() string {
	return s.user
}

// Delete marks the session to be deleted.
func (s *Session) Delete() {
	s.delete = true
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
		sessionID := r.FormValue(SessionParameter)
		if sessionID == "" {
			http.Redirect(w, r, mw.redirect, http.StatusSeeOther)
			return
		}
		token, ok := mw.cfg.Sessions.CheckKey(sessionID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		ctx := r.Context()

		var user string
		const userSQL = `SELECT nickname, last_access FROM sessions ` +
			`WHERE token = $1 AND last_access >= $2`

		expired := time.Now().Add(-mw.cfg.Sessions.MaxAge)

		switch err := mw.db.DB.QueryRowContext(ctx, userSQL, token, expired).Scan(&user); {
		case errors.Is(err, sql.ErrNoRows):
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		case err != nil:
			slog.ErrorContext(ctx, "cannot load session", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session := &Session{user: user}
		nctx := context.WithValue(ctx, sessionKey, session)
		defer func() {
			var sql string
			if session.delete {
				sql = `DELETE FROM sessions WHERE token = $1`
			} else {
				sql = `UPDATE sessions SET last_access = current_timestamp ` +
					`WHERE token = $1`
			}
			if _, err := mw.db.DB.ExecContext(ctx, sql, token); err != nil {
				slog.ErrorContext(ctx, "updating/deleting session failed", "error", err)
			}
			if session.delete {
				http.Redirect(w, r, mw.redirect, http.StatusSeeOther)
			}
		}()
		next(w, r.WithContext(nctx))
	}
}
