package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/JustSparx/SIPBXGO/internal/conference"
	"github.com/JustSparx/SIPBXGO/internal/store"
)

type confData struct {
	Rooms  []*store.Room
	Active []conference.RoomStatus
	Names  map[string]string
	Form   struct{ Number, Name, PIN string }
	Error  string
}

func (s *Server) confData(r *http.Request) (*confData, error) {
	rooms, err := s.store.ListRooms(r.Context())
	if err != nil {
		return nil, err
	}
	d := &confData{Rooms: rooms, Active: s.pbx.Conferences(), Names: map[string]string{}}
	for _, rm := range rooms {
		d.Names[rm.Number] = rm.Name
	}
	return d, nil
}

func (s *Server) conferences(w http.ResponseWriter, r *http.Request) {
	d, err := s.confData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "conferences", d)
}

func (s *Server) conferencesLive(w http.ResponseWriter, r *http.Request) {
	d, err := s.confData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderPart(w, r, "conferences", "live", d)
}

func (s *Server) createRoom(w http.ResponseWriter, r *http.Request) {
	room := &store.Room{
		Number: strings.TrimSpace(r.FormValue("number")),
		Name:   strings.TrimSpace(r.FormValue("name")),
		PIN:    strings.TrimSpace(r.FormValue("pin")),
	}
	err := s.store.CreateRoom(r.Context(), room)
	if err != nil {
		var msg string
		switch {
		case errors.Is(err, store.ErrNumberTaken):
			msg = room.Number + " is already an extension number."
		case errors.Is(err, store.ErrExists):
			msg = "Room " + room.Number + " already exists."
		case store.ValidateNumber(room.Number) != nil:
			msg = "Room numbers are 2 to 8 digits."
		default:
			msg = "The PIN must be up to 12 digits."
		}
		d, derr := s.confData(r)
		if derr != nil {
			s.serverError(w, r, derr)
			return
		}
		d.Error = msg
		d.Form.Number, d.Form.Name, d.Form.PIN = room.Number, room.Name, room.PIN
		s.render(w, r, http.StatusBadRequest, "conferences", d)
		return
	}
	s.log.Info("conference room created", "room", room.Number, "pin", room.PIN != "", "by", adminFrom(r))
	http.Redirect(w, r, "/conferences?ok=roomadded", http.StatusSeeOther)
}

func (s *Server) updateRoom(w http.ResponseWriter, r *http.Request) {
	room, err := s.store.GetRoom(r.Context(), r.PathValue("number"))
	if err != nil {
		http.Redirect(w, r, "/conferences", http.StatusSeeOther)
		return
	}
	room.Name = strings.TrimSpace(r.FormValue("name"))
	room.PIN = strings.TrimSpace(r.FormValue("pin"))
	if err := s.store.UpdateRoom(r.Context(), room); err != nil {
		d, derr := s.confData(r)
		if derr != nil {
			s.serverError(w, r, derr)
			return
		}
		d.Error = "The PIN must be up to 12 digits."
		s.render(w, r, http.StatusBadRequest, "conferences", d)
		return
	}
	s.log.Info("conference room updated", "room", room.Number, "pin", room.PIN != "", "by", adminFrom(r))
	http.Redirect(w, r, "/conferences?ok=roomsaved", http.StatusSeeOther)
}

func (s *Server) deleteRoom(w http.ResponseWriter, r *http.Request) {
	number := r.PathValue("number")
	if err := s.store.DeleteRoom(r.Context(), number); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("conference room deleted", "room", number, "by", adminFrom(r))
	http.Redirect(w, r, "/conferences?ok=roomgone", http.StatusSeeOther)
}
