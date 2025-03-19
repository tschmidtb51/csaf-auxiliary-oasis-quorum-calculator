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
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/auth"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/misc"
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
	me := auth.SessionFromContext(r.Context()).Nickname()
	if r.FormValue("delete") != "" {
		if users := slices.DeleteFunc(
			r.Form["users"],
			func(u string) bool {
				return u == "admin" || u == me
			}); len(users) > 0 &&
			!check(w, r, models.DeleteUsersByNickname(r.Context(), c.db, users...)) {
			return
		}
	}
	c.users(w, r)
}

func (c *Controller) userCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data := map[string]any{
		"Session": auth.SessionFromContext(ctx),
		"User":    auth.UserFromContext(ctx),
		"NewUser": &models.User{},
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "user_create.tmpl", data))
}

func (c *Controller) userCreateStore(w http.ResponseWriter, r *http.Request) {
	nuser := models.User{
		Nickname:  strings.TrimSpace(r.FormValue("nickname")),
		Firstname: nilString(strings.TrimSpace(r.FormValue("firstname"))),
		Lastname:  nilString(strings.TrimSpace(r.FormValue("lastname"))),
		IsAdmin:   r.FormValue("admin") == "admin",
	}
	var (
		ctx      = r.Context()
		errMsg   string
		password string
	)
	data := map[string]any{
		"Session": auth.SessionFromContext(ctx),
		"User":    auth.UserFromContext(ctx),
		"NewUser": &nuser,
	}

	if nuser.Nickname == "" {
		errMsg = "Login name is missing."
		goto renderTemplate
	}

	password = misc.RandomString(12)
	switch success, err := nuser.StoreNew(ctx, c.db, password); {
	case !check(w, r, err):
		return
	case !success:
		errMsg = fmt.Sprintf("User %q already exists.", nuser.Nickname)
		goto renderTemplate
	}
	data["Password"] = password
	check(w, r, c.tmpls.ExecuteTemplate(w, "user_created.tmpl", data))
	return

renderTemplate:
	if errMsg != "" {
		data["Error"] = errMsg
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "user_create.tmpl", data))
}
