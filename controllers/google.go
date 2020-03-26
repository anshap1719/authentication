package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/anshap1719/authentication/controllers/gen/google"
	"github.com/anshap1719/authentication/database"
	"github.com/anshap1719/authentication/models"
	"github.com/anshap1719/authentication/utils/auth"
	. "github.com/anshap1719/authentication/utils/ctx"
	"github.com/gofrs/uuid"
	"golang.org/x/oauth2"
	ght "golang.org/x/oauth2/google"
	"log"
	"net"
	"os"
	"reflect"
	"time"
)

// GoogleService implements the google resource.
type GoogleService struct {
	log     *log.Logger
	jwt     *auth.JWTSecurity
	session *SessionService
}

const (
	googleAuthentication = iota
	googleAttach
)

const (
	googleConnectionExpire = 30 * time.Minute
	googleRegisterExpire   = time.Hour
)

var googleConf = &oauth2.Config{
	ClientID:     os.Getenv("GoogleID"),
	ClientSecret: os.Getenv("GoogleSecret"),
	Scopes: []string{
		"email",
		"profile",
	},
	Endpoint: ght.Endpoint,
}

// NewGoogleService creates a google controller.
func NewGoogleService(log *log.Logger, jwt *auth.JWTSecurity, session *SessionService) google.Service {
	return &GoogleService{
		log:     log,
		jwt:     jwt,
		session: session,
	}
}

// Gets the URL the front-end should redirect the browser to in order to be
// authenticated with Google, and then register
func (s *GoogleService) RegisterURL(ctx context.Context, p *google.RegisterURLPayload) (res string, err error) {
	gc := &database.GoogleConnection{
		TimeCreated: time.Now(),
		Purpose:     googleAuthentication,
	}
	state, err := database.CreateGoogleConnection(ctx, gc)
	if err != nil {
		return "", google.MakeInternalServerError(err)
	}

	googleConf.RedirectURL = *p.RedirectURL
	return googleConf.AuthCodeURL(state.String()), nil
}

// Attaches a Google account to an existing user account, returns the URL the
// browser should be redirected to
func (s *GoogleService) AttachToAccount(ctx context.Context, p *google.AttachToAccountPayload) (res string, err error) {
	gc := &database.GoogleConnection{
		TimeCreated: time.Now(),
		Purpose:     googleAttach,
	}
	state, err := database.CreateGoogleConnection(ctx, gc)
	if err != nil {
		return "", google.MakeInternalServerError(err)
	}

	googleConf.RedirectURL = *p.RedirectURL
	return googleConf.AuthCodeURL(state.String()), nil
}

// Detaches a Google account from an existing user account.
func (s *GoogleService) DetachFromAccount(ctx context.Context, p *google.DetachFromAccountPayload) (err error) {
	uID := s.jwt.GetUserID(*p.Authorization)

	if getNumLoginMethods(ctx, uID) <= 1 {
		return google.MakeForbidden(errors.New("Cannot detach last login method"))
	}

	gID, err := database.QueryGoogleAccountUser(ctx, uID)
	if err == database.ErrGoogleAccountNotFound {
		return google.MakeNotFound(errors.New("User account is not connected to Google"))
	} else if err != nil {
		return google.MakeInternalServerError(err)
	}
	err = database.DeleteGoogleAccount(ctx, gID)
	if err != nil {
		return google.MakeInternalServerError(err)
	}
	return nil
}

type GoogleRegisterMedia struct {
	OauthKey, FirstName, LastName, Email string
	TimeCreated                          time.Time
}

// The endpoint that Google redirects the browser to after the user has
// authenticated
func (s *GoogleService) Receive(ctx context.Context, p *google.ReceivePayload) (res *google.UserMedia, err error) {
	gc, err := database.GetGoogleConnection(ctx, uuid.FromStringOrNil(*p.State))
	if err == database.ErrGoogleConnectionNotFound {
		return nil, google.MakeBadRequest(errors.New("Google connection must be created with other API methods"))
	} else if err != nil {
		return nil, google.MakeInternalServerError(err)
	}

	err = database.DeleteGoogleConnection(ctx, uuid.FromStringOrNil(*p.State))
	if err != nil {
		s.log.Println("Unable to delete Google connection")
	}

	if gc.TimeCreated.Add(googleConnectionExpire).Before(time.Now()) {
		return nil, google.MakeBadRequest(errors.New("Google token expired. Please try again"))
	}

	googleConf.RedirectURL = *p.RedirectURL
	token, err := googleConf.Exchange(ctx, *p.Code)
	if err != nil {
		return nil, google.MakeBadRequest(err)
	}

	tokenClient := googleConf.Client(ctx, token)

	resp, err := tokenClient.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {

		return nil, google.MakeInternalServerError(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, google.MakeBadRequest(errors.New("Invalid Google data"))
	}

	googleUser := &GoogleUser{}

	err = json.NewDecoder(resp.Body).Decode(googleUser)
	if err != nil {

		return nil, google.MakeInternalServerError(err)
	}

	gID := googleUser.GetEmail()
	if gID == "" {
		return nil, google.MakeBadRequest(errors.New("Unable to get Google user ID"))
	}

	switch gc.Purpose {
	case googleAuthentication:
		account, err := database.GetGoogleAccount(ctx, gID)
		if err == database.ErrGoogleAccountNotFound {
			gr := &database.GoogleRegister{
				GoogleEmail: gID,
				TimeCreated: time.Now(),
			}
			regID, err := database.CreateGoogleRegister(ctx, gr)
			if err != nil {

				return nil, google.MakeInternalServerError(err)
			}

			grm := &GoogleRegisterMedia{
				OauthKey:    regID.String(),
				FirstName:   googleUser.FirstName,
				LastName:    googleUser.LastName,
				Email:       googleUser.GetEmail(),
				TimeCreated: time.Now(),
			}

			return s.GoogleRegister(ctx, grm, regID.String())
		} else if err != nil {
			return nil, google.MakeInternalServerError(err)
		}

		u, err := database.GetUser(ctx, account.UserID)
		if err != nil {

			return nil, google.MakeInternalServerError(err)
		}

		remoteAddrInt := ctx.Value(RequestXForwardedForKey)
		var remoteAddr string

		if remoteAddrInt == nil || (reflect.ValueOf(remoteAddrInt).Kind() != reflect.String) {
			remoteAddr = ""
		} else {
			remoteAddr = remoteAddrInt.(string)
		}

		sesToken, authToken, err := s.session.loginUser(ctx, *u, remoteAddr, ctx.Value(RequestUserAgentKey).(string))
		if err != nil {
			return nil, google.MakeInternalServerError(err)
		}

		token := "Bearer " + authToken

		resp := &google.UserMedia{
			ID:             u.ID.Hex(),
			FirstName:      u.FirstName,
			LastName:       u.LastName,
			Email:          u.Email,
			ChangingEmail:  &u.ChangingEmail,
			VerifiedEmail:  u.VerifiedEmail,
			IsAdmin:        &u.IsAdmin,
			Authorization:  token,
			XSession:       sesToken,
		}

		return resp, nil

	case googleAttach:
		_, err := database.GetGoogleAccount(ctx, gID)
		if err == nil {
			return nil, google.MakeBadRequest(errors.New("This Google account is already attached to an account"))
		} else if err != database.ErrGoogleAccountNotFound {
			return nil, google.MakeInternalServerError(err)
		}

		uID := s.jwt.GetUserID(*p.Authorization)
		if uID == "" {
			return nil, google.MakeUnauthorized(errors.New("You must be logged in"))
		}
		_, err = database.GetUser(ctx, uID)
		if err == database.ErrUserNotFound {
			s.log.Println("Unable to get user account")
			return nil, google.MakeInternalServerError(errors.New("Unable to find user account"))
		} else if err != nil {
			return nil, google.MakeInternalServerError(err)
		}

		account := &database.GoogleAccount{
			GoogleEmail: gID,
			UserID:      uID,
		}
		err = database.CreateGoogleAccount(ctx, account)
		if err != nil {
			return nil, google.MakeInternalServerError(err)
		}
	default:
		s.log.Println("Bad Google receive type")
		return nil, google.MakeInternalServerError(errors.New("Invalid Google connection type"))
	}

	return nil, nil
}

type GoogleUser struct {
	ID        *string `json:"id,omitempty"`
	FirstName string  `json:"given_name,omitempty"`
	LastName  string  `json:"family_name,omitempty"`
	Email     *string `json:"email,omitempty"`
}

func (g *GoogleUser) GetEmail() string {
	if g.Email == nil {
		return ""
	}
	return *g.Email
}

func (s *GoogleService) GoogleRegister(ctx context.Context, gr *GoogleRegisterMedia, OauthKey string) (*google.UserMedia, error) {
	if gr.TimeCreated.Add(googleRegisterExpire).Before(time.Now()) {
		return nil, google.MakeNotFound(errors.New("Invalid registration key"))
	}

	var err error

	_, err = database.GetGoogleAccount(ctx, gr.Email)
	if err == nil {
		return nil, google.MakeForbidden(errors.New("This Google account is already attached to an account"))
	} else if err != database.ErrGoogleAccountNotFound {
		return nil, google.MakeInternalServerError(err)
	}
	_, err = database.QueryUserEmail(ctx, gr.Email)
	if err == nil {
		return nil, google.MakeForbidden(errors.New("This email is already in use " + "email " + gr.Email))
	} else if err != database.ErrUserNotFound {
		return nil, google.MakeInternalServerError(err)
	}

	remoteAddrInt := ctx.Value(RequestXForwardedForKey)
	var remoteAddr string

	if remoteAddrInt == nil || (reflect.ValueOf(remoteAddrInt).Kind() != reflect.String) {
		remoteAddr = ""
	} else {
		remoteAddr = remoteAddrInt.(string)
	}

	ipAddr, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ipAddr = remoteAddr
	}

	var gcaptch = ""

	newU := &models.User{
		FirstName:         gr.FirstName,
		LastName:          gr.LastName,
		Email:             gr.Email,
		VerifiedEmail:     true,
	}
	uID, err := createUser(ctx, newU, &gcaptch, ipAddr)
	if err == ErrInvalidRecaptcha {
		return nil, google.MakeBadRequest(err)
	} else if err != nil {
		return nil, google.MakeInternalServerError(err)
	}

	account := &database.GoogleAccount{
		GoogleEmail: gr.Email,
		UserID:      uID,
	}
	err = database.CreateGoogleAccount(ctx, account)
	if err != nil {
		return nil, google.MakeInternalServerError(err)
	}
	err = database.DeleteGoogleRegister(ctx, uuid.FromStringOrNil(OauthKey))
	if err != nil {
		s.log.Println("Unable to delete Google registration progress")
	}

	sesToken, authToken, err := s.session.loginUser(ctx, *newU, remoteAddr, ctx.Value(RequestUserAgentKey).(string))
	if err != nil {
		return nil, google.MakeInternalServerError(err)
	}

	token := "Bearer " + authToken

	newU.Email = gr.Email

	return &google.UserMedia{
		Email:          gr.Email,
		FirstName:      newU.FirstName,
		LastName:       newU.LastName,
		ID:             newU.ID.Hex(),
		ChangingEmail:  &newU.ChangingEmail,
		VerifiedEmail:  newU.VerifiedEmail,
		IsAdmin:        &newU.IsAdmin,
		Authorization:  token,
		XSession:       sesToken,
	}, nil
}
