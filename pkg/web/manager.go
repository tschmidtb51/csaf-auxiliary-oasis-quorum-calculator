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
	"strconv"
	"strings"
	"time"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/auth"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/models"
)

func (c *Controller) manager(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	meetings, err := models.LoadMeetings(
		ctx, c.db,
		transform(user.Committees(), idFromCommittee))
	if !check(w, r, err) {
		return
	}
	data := templateData{
		"Session":  auth.SessionFromContext(ctx),
		"User":     user,
		"Meetings": meetings,
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "manager.tmpl", data))
}

func (c *Controller) meetingsStore(w http.ResponseWriter, r *http.Request) {
	committeeID, err := strconv.ParseInt(r.FormValue("committee"), 10, 64)
	if !check(w, r, err) {
		return
	}
	ctx := r.Context()
	if r.FormValue("delete") != "" {
		filter := func(yield func(int64) bool) {
			for _, m := range r.Form["meetings"] {
				if id, err := strconv.ParseInt(m, 10, 64); err == nil && !yield(id) {
					return
				}
			}
		}
		if !check(w, r, models.DeleteMeetingsByID(ctx, c.db, committeeID, filter)) {
			return
		}
	}
	user := auth.UserFromContext(ctx)
	remaining, err := models.LoadMeetings(ctx, c.db,
		transform(user.Committees(), idFromCommittee))
	if !check(w, r, err) {
		return
	}
	data := templateData{
		"Session":  auth.SessionFromContext(ctx),
		"User":     user,
		"Meetings": remaining,
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "manager.tmpl", data))
}

func (c *Controller) meetingCreate(w http.ResponseWriter, r *http.Request) {
	committee, err := strconv.ParseInt(r.FormValue("committee"), 10, 64)
	if !checkParam(w, err) {
		return
	}
	ctx := r.Context()
	now := time.Now()
	data := templateData{
		"Session": auth.SessionFromContext(ctx),
		"User":    auth.UserFromContext(ctx),
		"Meeting": &models.Meeting{
			StartTime: now,
			StopTime:  now.Add(time.Hour),
		},
		"Committee": committee,
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "meeting_create.tmpl", data))
}

func (c *Controller) meetingCreateStore(w http.ResponseWriter, r *http.Request) {
	committee, err := strconv.ParseInt(r.FormValue("committee"), 10, 64)
	if !checkParam(w, err) {
		return
	}
	var (
		startTime   = r.FormValue("start_time")
		duration    = r.FormValue("duration")
		description = nilString(strings.TrimSpace(r.FormValue("description")))
		s, errS     = time.ParseInLocation("2006-01-02T15:04", startTime, time.UTC)
		d, errD     = parseDuration(duration)
		ctx         = r.Context()
	)
	meeting := models.Meeting{
		CommitteeID: committee,
		Description: description,
	}
	data := templateData{
		"Session":   auth.SessionFromContext(ctx),
		"User":      auth.UserFromContext(ctx),
		"Meeting":   &meeting,
		"Committee": committee,
	}
	switch {
	case errS != nil && errD != nil:
		data.error("Start time and duration are invalid.")
		s, d = time.Now(), time.Hour
	case errS != nil:
		data.error("Start time is invalid.")
		s = time.Now()
	case errD != nil:
		data.error("Duration is invalid.")
		d = time.Hour
	}
	meeting.StartTime = s
	meeting.StopTime = s.Add(d)
	if data.hasError() {
		check(w, r, c.tmpls.ExecuteTemplate(w, "meeting_create.tmpl", data))
		return
	}
	seq := slices.Values([]int64{committee})
	meetings, err := models.LoadMeetings(ctx, c.db, seq)
	if !check(w, r, err) {
		return
	}
	if meetings.Contains(models.OverlapFilter(meeting.StartTime, meeting.StopTime)) {
		data.error("Time range collides with another meeting in this committee.")
		check(w, r, c.tmpls.ExecuteTemplate(w, "meeting_create.tmpl", data))
		return
	}
	if !check(w, r, meeting.StoreNew(ctx, c.db)) {
		return
	}
	c.manager(w, r)
}
