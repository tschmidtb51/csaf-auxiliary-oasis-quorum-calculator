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

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/auth"
)

func (c *Controller) user(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data := map[string]any{
		"Session": auth.SessionFromContext(ctx),
		"User":    auth.UserFromContext(ctx),
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "user.tmpl", data))
}

func (c *Controller) userStore(w http.ResponseWriter, r *http.Request) {
	var (
		firstname       = r.FormValue("firstname")
		lastname        = r.FormValue("lastname")
		password        = r.FormValue("password")
		passwordConfirm = r.FormValue("password2")
	)
	changed := false
	change := func(s **string, v string) {
		switch {
		case v == "" && *s == nil:
			return
		case v != "" && *s != nil && v == **s:
			return
		case v == "" && *s != nil:
			*s = nil
		default:
			*s = &v
		}
		changed = true
	}

	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	change(&user.Firstname, firstname)
	change(&user.Lastname, lastname)

	var errMsg string
	if password != "" || passwordConfirm != "" {
		if password != passwordConfirm {
			errMsg = "Password and confirmation do not match."
			goto renderTemplate
		}
		if len([]rune(password)) < 8 {
			errMsg = "Password too short (need at least 8 characters)"
			goto renderTemplate
		}
		change(&user.Password, password)
	}
	if changed && !check(w, r, user.Store(ctx, c.db)) {
		return
	}
renderTemplate:
	data := map[string]any{
		"Session": auth.SessionFromContext(ctx),
		"User":    user,
	}
	if errMsg != "" {
		data["Error"] = errMsg
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "user.tmpl", data))
}
