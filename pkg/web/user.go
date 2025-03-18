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
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/auth"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/models"
)

func (c *Controller) users(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, err := models.LoadAllUsers(ctx, c.db)
	if !check(w, r, err) {
		return
	}
	data := map[string]any{
		"Users":   users,
		"Session": auth.SessionFromContext(ctx),
		"User":    auth.UserFromContext(ctx),
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "users.tmpl", data))
}

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
		firstname       = strings.TrimSpace(r.FormValue("firstname"))
		lastname        = strings.TrimSpace(r.FormValue("lastname"))
		password        = strings.TrimSpace(r.FormValue("password"))
		passwordConfirm = strings.TrimSpace(r.FormValue("password2"))
	)
	change, changed := changer()

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
		if utf8.RuneCountInString(password) < 8 {
			errMsg = "Password too short (need at least 8 characters)"
			goto renderTemplate
		}
		change(&user.Password, password)
	}
	if *changed && !check(w, r, user.Store(ctx, c.db)) {
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

func (c *Controller) usersStore(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("delete") != "" {
		if users := slices.DeleteFunc(
			r.Form["users"],
			func(u string) bool { return u == "admin" }); len(users) > 0 &&
			!check(w, r, models.DeleteUsersByNickname(r.Context(), c.db, users...)) {
			return
		}
	}
	c.users(w, r)
}
