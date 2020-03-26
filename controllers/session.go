package controllers

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/anshap1719/authentication/controllers/gen/session"
	"github.com/anshap1719/authentication/database"
	"github.com/anshap1719/authentication/models"
	"github.com/anshap1719/authentication/utils/auth"
	. "github.com/anshap1719/authentication/utils/ctx"
	"github.com/anshap1719/authentication/utils/iplocation"
	"github.com/gofrs/uuid"
	"github.com/mssola/user_agent"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"time"
)

var (
	SessionTime = 7 * 24 * time.Hour // 1 week
	TokenTime   = 10 * time.Minute
)

// SessionService implements the session resource.
type SessionService struct {
	log *log.Logger
	jwt *auth.JWTSecurity
}

// NewSessionService creates a session controller.
func NewSessionService(log *log.Logger, jwt *auth.JWTSecurity) *SessionService {
	if os.Getenv("STAGE") == "TEST" {
		TokenTime = 7 * 24 * time.Hour
	}

	return &SessionService{
		log: log,
		jwt: jwt,
	}
}

// Take a user's session token and refresh it, also returns a new
// authentication token
func (s *SessionService) Refresh(ctx context.Context, p *session.RefreshPayload) (res *session.RefreshResult, err error) {
	sesID := s.jwt.GetSessionCode(*p.XSession)
	if sesID == "" {
		return nil, session.MakeBadRequest(errors.New("Invalid session ID"))
	}
	sess, err := database.GetSession(ctx, sesID)
	if err == database.ErrSessionNotFound {
		return nil, session.MakeUnauthorized(errors.New("Session not found"))
	} else if err != nil {
		return nil, session.MakeInternalServerError(err)
	}
	if !sess.LastUsed.Add(SessionTime).After(time.Now()) {
		return nil, session.MakeUnauthorized(errors.New("Session not found"))
	}

	updatedSession := s.createSession(sess.UserID, sess.IsAdmin, ctx.Value(RequestXForwardedForKey).(string), ctx.Value(RequestUserAgentKey).(string))
	updatedSession.ID = sess.ID
	err = database.UpdateSession(ctx, updatedSession)
	if err != nil {
		return nil, session.MakeInternalServerError(err)
	}

	sessToken, err := s.jwt.SignSessionToken(SessionTime, sess.ID.Hex())
	if err != nil {
		return nil, session.MakeInternalServerError(err)
	}

	authToken, err := s.jwt.SignAuthToken(TokenTime, sess.ID.Hex(), sess.UserID, sess.IsAdmin)
	if err != nil {
		return nil, session.MakeInternalServerError(err)
	}

	token := "Bearer " + authToken

	return &session.RefreshResult{
		Authorization: &token,
		XSession:      &sessToken,
	}, nil
}

// Takes a user's auth token, and logs-out the session associated with it
func (s *SessionService) Logout(ctx context.Context, p *session.LogoutPayload) (err error) {
	sesID := s.jwt.GetSessionFromAuth(*p.Authorization)

	if err := database.DeleteSession(ctx, sesID); err != nil {
		return session.MakeInternalServerError(err)
	}

	return nil
}

// Logout all sessions for the current user except their current session
func (s *SessionService) LogoutOther(ctx context.Context, p *session.LogoutOtherPayload) (err error) {
	uID := s.jwt.GetUserID(*p.Authorization)
	sesID := s.jwt.GetSessionFromAuth(*p.Authorization)

	err2 := logoutAllSessionsBut(ctx, uID, sesID)
	if err2 != nil {
		return session.MakeInternalServerError(err)
	}

	return nil
}

// Logout of a specific session
func (s *SessionService) LogoutSpecific(ctx context.Context, p *session.LogoutSpecificPayload) (err error) {
	uID := s.jwt.GetUserID(*p.Authorization)
	sesID := *p.SessionID
	if sesID == "" {
		return session.MakeBadRequest(errors.New("Session ID must be provided"))
	}

	sess, err := database.GetSession(ctx, sesID)
	if err == database.ErrSessionNotFound {
		return session.MakeNotFound(errors.New("No session with the given ID found"))
	} else if err != nil {
		return session.MakeInternalServerError(err)
	}
	if sess.UserID != uID {
		return session.MakeNotFound(errors.New("No session with the given ID found"))
	}

	err = database.DeleteSession(ctx, sesID)
	if err != nil {
		return session.MakeInternalServerError(err)
	}

	return nil
}

// Gets all of the sessions that are associated with the currently logged in
// user
func (s *SessionService) GetSessions(ctx context.Context, p *session.GetSessionsPayload) (res *session.AllSessions, err error) {
	userID := s.jwt.GetUserID(*p.Authorization)
	sesID := s.jwt.GetSessionFromAuth(*p.Authorization)
	sessions, err := database.QuerySessionFromAccount(ctx, userID)
	if err != nil {
		return nil, session.MakeInternalServerError(err)
	}

	resp := &session.AllSessions{
		CurrentSession: &session.Session{},
		OtherSessions:  []*session.Session{},
	}

	for _, v := range sessions {
		s := database.SessionToSession(v)
		if v.Latitude != "" && v.Longitude != "" {
			mapURL, err := getMapURL(v.Latitude, v.Longitude)
			if err != nil {
				return nil, session.MakeInternalServerError(err)
			}
			s.MapURL = mapURL
		}
		if v.ID.Hex() == sesID {
			resp.CurrentSession = s
		} else {
			resp.OtherSessions = append(resp.OtherSessions, s)
		}
	}

	return resp, nil
}

// Redeems a login token for credentials
func (s *SessionService) RedeemToken(ctx context.Context, p *session.RedeemTokenPayload) (res *session.RedeemTokenResult, err error) {
	t, err := database.GetLoginToken(ctx, uuid.FromStringOrNil(p.Token))
	if err == database.ErrLoginTokenNotFound {
		return nil, session.MakeForbidden(errors.New("Token does not exist"))
	} else if err != nil {
		return nil, session.MakeInternalServerError(err)
	}

	if t.TimeExpire.Before(time.Now()) {
		return nil, session.MakeForbidden(errors.New("Token does not exist"))
	}

	user, err := database.GetUser(ctx, t.UserID)
	if err != nil {
		return nil, session.MakeInternalServerError(err)
	}

	remoteAddrInt := ctx.Value(RequestXForwardedForKey)
	var remoteAddr string

	if remoteAddrInt == nil || (reflect.ValueOf(remoteAddrInt).Kind() != reflect.String) {
		remoteAddr = ""
	} else {
		remoteAddr = remoteAddrInt.(string)
	}

	sesToken, authToken, err := s.loginUser(ctx, *user, remoteAddr, ctx.Value(RequestUserAgentKey).(string))
	if err != nil {
		return nil, session.MakeInternalServerError(err)
	}

	err = database.DeleteLoginToken(ctx, t.Token)
	if err != nil {
		s.log.Println("Unable to delete login token")
	}

	token := "Bearer " + authToken

	return &session.RedeemTokenResult{
		Authorization: &token,
		XSession:      &sesToken,
	}, nil
}

// Deletes all the sessions that have expired
func (s *SessionService) CleanSessions(ctx context.Context, p *session.CleanSessionsPayload) (err error) {
	if s.jwt.IsAdmin(*p.Authorization) {
		sessionIds, err := database.QuerySessionOld(ctx, time.Now().Add(-SessionTime))
		if err != nil {
			return nil
		}

		for start := 0; start < len(sessionIds); start += 500 {
			end := start + 500
			if end > len(sessionIds) {
				end = len(sessionIds)
			}
			_ = database.DeleteSessionMulti(ctx, sessionIds[start:end])
		}

		return nil
	} else {
		return session.MakeNotFound(errors.New("requested resource doesn't exist"))
	}
}

// Cleans old login tokens from the database
func (s *SessionService) CleanLoginToken(ctx context.Context, p *session.CleanLoginTokenPayload) (err error) {
	if s.jwt.IsAdmin(*p.Authorization) {
		tokens, err := database.QueryLoginTokenOld(ctx, time.Now())
		if err != nil {
			return nil
		}

		for start := 0; start < len(tokens); start += 500 {
			end := start + 500
			if end > len(tokens) {
				end = len(tokens)
			}
			_ = database.DeleteLoginTokenMulti(ctx, tokens[start:end])
		}

		return nil
	} else {
		return session.MakeNotFound(errors.New("the requested resource was not found"))
	}
}

// Cleans old account merge tokens from the database
func (s *SessionService) CleanMergeToken(ctx context.Context, p *session.CleanMergeTokenPayload) (err error) {
	if s.jwt.IsAdmin(*p.Authorization) {
		tokens, err := database.QueryMergeTokenOld(ctx, time.Now())
		if err != nil {
			return nil
		}

		for start := 0; start < len(tokens); start += 500 {
			end := start + 500
			if end > len(tokens) {
				end = len(tokens)
			}
			_ = database.DeleteMergeTokenMulti(ctx, tokens[start:end])
		}

		return nil
	} else {
		return session.MakeNotFound(errors.New("the requested resource was not found"))
	}
}

func (s *SessionService) createSession(userID string, isAdmin bool, RemoteAddr, UserAgent string) *database.Session {
	ip, _, err := net.SplitHostPort(RemoteAddr)
	if err != nil {
		ip = RemoteAddr
	}

	ua := user_agent.New(UserAgent)
	osInfo := ua.OSInfo()
	if osInfo.Name == "OS" {
		osInfo.Name = ua.Platform()
	}
	browse, vers := ua.Browser()

	place, latitude, longitude := getIPLocation(ip)

	newSession := &database.Session{
		UserID:         userID,
		LastUsed:       time.Now(),
		IP:             ip,
		Os:             osInfo.Name + " " + osInfo.Version,
		Browser:        browse + " " + vers,
		Location:       place,
		Latitude:       latitude,
		Longitude:      longitude,
		IsMobile:       ua.Mobile(),
		IsAdmin:        isAdmin,
	}

	return newSession
}

func (s *SessionService) loginUser(ctx context.Context, user models.User, remoteAddr, userAgent string) (sessionToken string, authToken string, err error) {
	newSession := s.createSession(user.ID.Hex(), user.IsAdmin, remoteAddr, userAgent)
	sesID, err := database.CreateSession(ctx, newSession)
	if err != nil {
		return "", "", err
	}

	sessionToken, err = s.jwt.SignSessionToken(SessionTime, sesID)
	if err != nil {
		return "", "", err
	}

	authToken, err = s.jwt.SignAuthToken(TokenTime, sesID, user.ID.Hex(), user.IsAdmin)
	if err != nil {
		return "", "", err
	}

	return sessionToken, authToken, nil
}

func logoutAllSessionsBut(ctx context.Context, userID, sessionID string) error {
	sesIds, err := database.QuerySessionIds(ctx, userID)
	if err != nil {
		return err
	}

	for i, v := range sesIds {
		if v == sessionID {
			sesIds = append(sesIds[:i], sesIds[i+1:]...)
			break
		}
	}

	err = database.DeleteSessionMulti(ctx, sesIds)
	if err != nil {
		return err
	}
	return nil
}

func getIPLocation(remoteAddr string) (place string, latitude string, longitude string) {
	loc, err := iplocation.GetLocationByIp(remoteAddr)
	if err != nil {
		return "", "", ""
	}

	place = fmt.Sprintf("%s, %s, %s", loc.City, loc.RegionName, loc.CountryName)
	latitude = strconv.FormatFloat(float64(loc.Lat), 'f', 6, 32)
	longitude = strconv.FormatFloat(float64(loc.Lon), 'f', 6, 32)

	return place, latitude, longitude
}

func getMapURL(latitude, longitude string) (string, error) {
	u, err := url.Parse(fmt.Sprintf("https://maps.googleapis.com/maps/api/staticmap?center=%s,%ssize=500x500&markers=%s,%s&format=jpg&zoom=7&key=%s", latitude, longitude, latitude, longitude, os.Getenv("GoogleMapsKey")))
	if err != nil {
		return "", err
	}

	sign, err := base64.URLEncoding.DecodeString(os.Getenv("GoogleMapsSigning"))
	if err != nil {
		return "", err
	}

	h := hmac.New(sha1.New, sign)
	_, err = io.WriteString(h, u.RequestURI())
	if err != nil {
		return "", err
	}

	signature := base64.URLEncoding.EncodeToString(h.Sum(nil))
	u.RawQuery += "&signature=" + signature
	return u.String(), nil
}
