// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

package web

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/auth"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/misc"
	"github.com/csaf-auxiliary/oasis-quorum-calculator/pkg/models"
)

func (c *Controller) chair(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	meetings, err := models.LoadMeetings(
		ctx, c.db,
		misc.Map(user.Committees(), (*models.Committee).GetID))
	if !check(w, r, err) {
		return
	}
	data := templateData{
		"Session":  auth.SessionFromContext(ctx),
		"User":     user,
		"Meetings": meetings,
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "chair.tmpl", data))
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
		misc.Map(user.Committees(), (*models.Committee).GetID))
	if !check(w, r, err) {
		return
	}
	data := templateData{
		"Session":  auth.SessionFromContext(ctx),
		"User":     user,
		"Meetings": remaining,
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "chair.tmpl", data))
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
		description = nilString(strings.TrimSpace(r.FormValue("description")))
		startTime   = r.FormValue("start_time")
		duration    = r.FormValue("duration")
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
	meetings, err := models.LoadMeetings(ctx, c.db, misc.Values(committee))
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
	c.chair(w, r)
}

func (c *Controller) meetingEdit(w http.ResponseWriter, r *http.Request) {
	var (
		meetingID, err1   = strconv.ParseInt(r.FormValue("meeting"), 10, 64)
		committeeID, err2 = strconv.ParseInt(r.FormValue("committee"), 10, 64)
	)
	if !checkParam(w, err1, err2) {
		return
	}
	ctx := r.Context()
	meeting, err := models.LoadMeeting(ctx, c.db, meetingID, committeeID)
	if !check(w, r, err) {
		return
	}
	if meeting == nil {
		c.chair(w, r)
		return
	}
	data := templateData{
		"Session":   auth.SessionFromContext(ctx),
		"User":      auth.UserFromContext(ctx),
		"Meeting":   meeting,
		"Committee": committeeID,
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "meeting_edit.tmpl", data))
}

func (c *Controller) meetingEditStore(w http.ResponseWriter, r *http.Request) {
	var (
		meetingID, err1   = strconv.ParseInt(r.FormValue("meeting"), 10, 64)
		committeeID, err2 = strconv.ParseInt(r.FormValue("committee"), 10, 64)
		description       = nilString(strings.TrimSpace(r.FormValue("description")))
		startTime         = r.FormValue("start_time")
		duration          = r.FormValue("duration")
		s, errS           = time.ParseInLocation("2006-01-02T15:04", startTime, time.UTC)
		d, errD           = parseDuration(duration)
		ctx               = r.Context()
	)
	if !checkParam(w, err1, err2) {
		return
	}
	meeting, err := models.LoadMeeting(ctx, c.db, meetingID, committeeID)
	if !check(w, r, err) {
		return
	}
	if meeting == nil || meeting.Status == models.MeetingConcluded {
		c.chair(w, r)
		return
	}
	meeting.Description = description
	data := templateData{
		"Session":   auth.SessionFromContext(ctx),
		"User":      auth.UserFromContext(ctx),
		"Meeting":   meeting,
		"Committee": committeeID,
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
		check(w, r, c.tmpls.ExecuteTemplate(w, "meeting_edit.tmpl", data))
		return
	}
	meetings, err := models.LoadMeetings(ctx, c.db, misc.Values(committeeID))
	if !check(w, r, err) {
		return
	}
	if meetings.Contains(
		models.OverlapFilter(meeting.StartTime, meeting.StopTime, meetingID)) {
		data.error("Time range collides with another meeting in this committee.")
		check(w, r, c.tmpls.ExecuteTemplate(w, "meeting_edit.tmpl", data))
		return
	}
	if !check(w, r, meeting.Store(ctx, c.db)) {
		return
	}
	c.chair(w, r)
}

func (c *Controller) meetingStatus(w http.ResponseWriter, r *http.Request) {
	var (
		meetingID, err1   = strconv.ParseInt(r.FormValue("meeting"), 10, 64)
		committeeID, err2 = strconv.ParseInt(r.FormValue("committee"), 10, 64)
		ctx               = r.Context()
	)
	if !checkParam(w, err1, err2) {
		return
	}
	meeting, err := models.LoadMeeting(ctx, c.db, meetingID, committeeID)
	if !check(w, r, err) {
		return
	}
	if meeting == nil {
		c.chair(w, r)
		return
	}
	members, err := models.LoadCommitteeUsers(ctx, c.db, committeeID)
	if !check(w, r, err) {
		return
	}
	attendees, err := meeting.Attendees(ctx, c.db)
	if !check(w, r, err) {
		return
	}
	committee, err := models.LoadCommittee(ctx, c.db, committeeID)
	if !check(w, r, err) {
		return
	}

	var numVoters, attendingVoters, numNonVoters, numMembers int
	for _, member := range members {
		if ms := member.FindMembership(committee.Name); ms != nil &&
			ms.HasRole(models.MemberRole) {
			switch ms.Status {
			case models.Voting:
				{
					numVoters++
					if attendees[member.Nickname] {
						attendingVoters++
					}
				}
			case models.NoneVoting:
				numNonVoters++
			case models.Member:
				numMembers++
			}
		}
	}

	quorum := models.Quorum{
		Number:  1 + numVoters/2,
		Reached: attendingVoters >= (1 + numVoters/2),
	}

	count := models.MemberCount{
		Total:     len(members),
		Member:    numMembers,
		Voting:    numVoters,
		NonVoting: numNonVoters,
	}

	data := templateData{
		"Session":   auth.SessionFromContext(ctx),
		"User":      auth.UserFromContext(ctx),
		"Meeting":   meeting,
		"Members":   members,
		"Attendees": attendees,
		"Quorum":    &quorum,
		"Count":     &count,
		"Committee": committee,
	}
	check(w, r, c.tmpls.ExecuteTemplate(w, "meeting_status.tmpl", data))
}

func (c *Controller) meetingStatusStore(w http.ResponseWriter, r *http.Request) {
	var (
		meetingID, err1     = strconv.ParseInt(r.FormValue("meeting"), 10, 64)
		committeeID, err2   = strconv.ParseInt(r.FormValue("committee"), 10, 64)
		meetingStatus, err3 = models.ParseMeetingStatus(r.FormValue("status"))
		ctx                 = r.Context()
	)
	if !checkParam(w, err1, err2, err3) {
		return
	}
	// In case we
	if meetingStatus == models.MeetingConcluded {
		var err error
		if !check(w, r, err) {
			return
		}
	}
	// This is only called if the update was successful.
	onSuccess := func(ctx context.Context, tx *sql.Tx) error {
		if meetingStatus != models.MeetingConcluded {
			return nil
		}
		prevAttendees, err := models.PreviousMeetingAttendeesTx(ctx, tx, meetingID)
		if err != nil {
			return err
		}
		if prevAttendees == nil { // There was no last meeting.
			return nil
		}
		currAttendees, err := models.MeetingAttendeesTx(ctx, tx, meetingID)
		if err != nil {
			return err
		}
		users, err := models.LoadCommitteeUsersTx(ctx, tx, committeeID)
		if err != nil {
			return err
		}
		crit := models.MembershipByID(committeeID)
		for _, user := range users {
			ms := user.FindMembershipCriterion(crit)
			if ms == nil || ms.Status == models.NoneVoting {
				continue
			}
			votingCurr, wasInCurr := currAttendees[user.Nickname]
			votingPrev, wasInPrev := prevAttendees[user.Nickname]

			_, _ = votingCurr, wasInCurr
			_, _ = votingPrev, wasInPrev

			// TODO: To be continued.

		}
		// TODO: Update voting rights of committee members.
		slog.Info("TODO: Need to update the voting rights")
		return nil
	}
	if !check(w, r, models.UpdateMeetingStatus(
		ctx, c.db,
		meetingID, committeeID, meetingStatus,
		onSuccess,
	)) {
		return
	}
	c.meetingStatus(w, r)
}

func (c *Controller) meetingAttendStore(w http.ResponseWriter, r *http.Request) {
	var (
		meetingID, err1   = strconv.ParseInt(r.FormValue("meeting"), 10, 64)
		committeeID, err2 = strconv.ParseInt(r.FormValue("committee"), 10, 64)
		ctx               = r.Context()
	)
	if !checkParam(w, err1, err2) {
		return
	}
	meeting, err := models.LoadMeeting(ctx, c.db, meetingID, committeeID)
	if !check(w, r, err) {
		return
	}
	if meeting == nil || meeting.Status != models.MeetingRunning {
		c.meetingStatus(w, r)
		return
	}
	users, err := models.LoadCommitteeUsers(ctx, c.db, committeeID)
	if !check(w, r, err) {
		return
	}
	seq := func(yield func(string, bool) bool) {
		crit := models.MembershipByID(committeeID)
		for _, nickname := range r.Form["attend"] {
			// Check if the given nickname is really in the members of this committee.
			idx := slices.IndexFunc(users, func(u *models.User) bool {
				return u.Nickname == nickname
			})
			if idx == -1 {
				continue
			}
			if ms := users[idx].FindMembershipCriterion(crit); ms != nil {
				// Remember if voting is allowed at the moment.
				// This may change in the future.
				voting := ms.Status == models.Voting && ms.HasRole(models.MemberRole)
				if !yield(nickname, voting) {
					return
				}
			}
		}
	}
	if !check(w, r, models.UpdateAttendees(ctx, c.db, meetingID, seq)) {
		return
	}
	c.meetingStatus(w, r)
}
