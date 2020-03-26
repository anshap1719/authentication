package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/anshap1719/authentication/controllers/gen/linkedin"
	"github.com/anshap1719/authentication/database"
	"github.com/anshap1719/authentication/models"
	"github.com/anshap1719/authentication/utils/auth"
	. "github.com/anshap1719/authentication/utils/ctx"
	"github.com/gofrs/uuid"
	"golang.org/x/oauth2"
	ght "golang.org/x/oauth2/linkedin"
	"log"
	"net"
	"os"
	"reflect"
	"time"
)

// LinkedinService implements the linkedin resource.
type LinkedinService struct {
	log     *log.Logger
	jwt     *auth.JWTSecurity
	session *SessionService
}

const (
	linkedinRegister = iota
	linkedinLogin
	linkedinAttach
)

const (
	linkedinConnectionExpire = 30 * time.Minute
	linkedinRegisterExpire   = time.Hour
)

var linkedinConf = &oauth2.Config{
	ClientID:     os.Getenv("LinkedInID"),
	ClientSecret: os.Getenv("LinkedInSecret"),
	Scopes: []string{
		"r_emailaddress",
		"r_basicprofile",
	},
	Endpoint:    ght.Endpoint,
	RedirectURL: os.Getenv("ClientURL") + "/social/linkedin/receive",
}

// NewLinkedinService creates a linkedin controller.
func NewLinkedinService(log *log.Logger, jwt *auth.JWTSecurity, session *SessionService) linkedin.Service {
	return &LinkedinService{
		log:     log,
		jwt:     jwt,
		session: session,
	}
}

// Gets the URL the front-end should redirect the browser to in order to be
// authenticated with Linkedin, and then register
func (s *LinkedinService) RegisterURL(ctx context.Context, p *linkedin.RegisterURLPayload) (res string, err error) {
	gc := &database.LinkedinConnection{
		TimeCreated: time.Now(),
		Purpose:     linkedinRegister,
	}
	state, err := database.CreateLinkedinConnection(ctx, gc)
	if err != nil {
		return "", linkedin.MakeInternalServerError(err)
	}
	return linkedinConf.AuthCodeURL(state.String()), nil
}

// Attaches a Linkedin account to an existing user account, returns the URL the
// browser should be redirected to
func (s *LinkedinService) AttachToAccount(ctx context.Context, p *linkedin.AttachToAccountPayload) (res string, err error) {
	gc := &database.LinkedinConnection{
		TimeCreated: time.Now(),
		Purpose:     linkedinAttach,
	}
	state, err := database.CreateLinkedinConnection(ctx, gc)
	if err != nil {
		return "", linkedin.MakeInternalServerError(err)
	}
	return linkedinConf.AuthCodeURL(state.String()), nil
}

// Detaches a Linkedin account from an existing user account.
func (s *LinkedinService) DetachFromAccount(ctx context.Context, p *linkedin.DetachFromAccountPayload) (err error) {
	uID := s.jwt.GetUserID(*p.Authorization)

	if getNumLoginMethods(ctx, uID) <= 1 {
		return linkedin.MakeForbidden(errors.New("Cannot detach last login method"))
	}

	gID, err := database.QueryLinkedinAccountUser(ctx, uID)
	if err == database.ErrLinkedinAccountNotFound {
		return linkedin.MakeNotFound(errors.New("User account is not connected to Linkedin"))
	} else if err != nil {
		return linkedin.MakeInternalServerError(err)
	}
	err = database.DeleteLinkedinAccount(ctx, gID)
	if err != nil {
		return linkedin.MakeInternalServerError(err)
	}
	return nil
}

type LinkedinUser struct {
	ID        string `json:"id,omitempty" bson:"id,omitempty"`
	FirstName string `json:"firstName,omitempty" bson:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty" bson:"lastName,omitempty"`
	Email     string `json:"emailAddress,omitempty" bson:"emailAddress,omitempty"`
}

type LinkedinRegisterMedia struct {
	OauthKey    string `json:"id,omitempty" bson:"id,omitempty"`
	FirstName   string `json:"firstName,omitempty" bson:"firstName,omitempty"`
	LastName    string `json:"lastName,omitempty" bson:"lastName,omitempty"`
	Email       string `json:"emailAddress,omitempty" bson:"emailAddress,omitempty"`
	TimeCreated time.Time
}

// The endpoint that Linkedin redirects the browser to after the user has
// authenticated
func (s *LinkedinService) Receive(ctx context.Context, p *linkedin.ReceivePayload) (res *linkedin.UserMedia, err error) {
	gc, err := database.GetLinkedinConnection(ctx, uuid.FromStringOrNil(*p.State))
	if err == database.ErrLinkedinConnectionNotFound {
		return nil, linkedin.MakeBadRequest(errors.New("Linkedin connection must be created with other API methods"))
	} else if err != nil {
		return nil, linkedin.MakeInternalServerError(err)
	}
	err = database.DeleteLinkedinConnection(ctx, uuid.FromStringOrNil(*p.State))
	if err != nil {
		s.log.Println("Unable to delete Linkedin connection")
	}
	if gc.TimeCreated.Add(linkedinConnectionExpire).Before(time.Now()) {
		return nil, linkedin.MakeBadRequest(errors.New("Linkedin token expired. Please try again"))
	}

	token, err := linkedinConf.Exchange(ctx, *p.Code)
	if err != nil {
		return nil, linkedin.MakeBadRequest(err)
	}

	tokenClient := linkedinConf.Client(ctx, token)
	resp, err := tokenClient.Get("https://api.linkedin.com/v1/people/~:(id,first-name,email-address,last-name)?format=json")
	if err != nil {
		return nil, linkedin.MakeInternalServerError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, linkedin.MakeBadRequest(errors.New("Invalid Linkedin data"))
	}
	linkedinUser := &LinkedinUser{}
	err = json.NewDecoder(resp.Body).Decode(linkedinUser)
	if err != nil {
		return nil, linkedin.MakeInternalServerError(err)
	}

	gID := linkedinUser.Email
	if gID == "" {
		return nil, linkedin.MakeBadRequest(errors.New("Unable to get Linkedin user ID"))
	}

	switch gc.Purpose {
	case linkedinLogin:
		account, err := database.GetLinkedinAccount(ctx, gID)
		if err == database.ErrLinkedinAccountNotFound {
			_, err := database.GetLinkedinAccount(ctx, gID)
			if err == nil {
				return nil, linkedin.MakeBadRequest(errors.New("This Linkedin account is already attached to an account"))
			} else if err != database.ErrLinkedinAccountNotFound {
				return nil, linkedin.MakeInternalServerError(err)
			}

			gr := &database.LinkedinRegister{
				LinkedinEmail: gID,
				TimeCreated:   time.Now(),
			}
			regID, err := database.CreateLinkedinRegister(ctx, gr)
			if err != nil {
				return nil, linkedin.MakeInternalServerError(err)
			}

			grm := &LinkedinRegisterMedia{
				OauthKey:    regID.String(),
				FirstName:   linkedinUser.FirstName,
				LastName:    linkedinUser.LastName,
				Email:       linkedinUser.Email,
				TimeCreated: gr.TimeCreated,
			}

			return s.LinkedinRegister(ctx, grm, regID.String())
		} else if err != nil {
			return nil, linkedin.MakeInternalServerError(err)
		}
		u, err := database.GetUser(ctx, account.UserID)
		if err != nil {
			return nil, linkedin.MakeInternalServerError(err)
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
			return nil, linkedin.MakeInternalServerError(err)
		}

		token := "Bearer " + authToken

		resp := &linkedin.UserMedia{
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
	case linkedinAttach:
		_, err := database.GetLinkedinAccount(ctx, gID)
		if err == nil {
			return nil, linkedin.MakeBadRequest(errors.New("This Linkedin account is already attached to an account"))
		} else if err != database.ErrLinkedinAccountNotFound {
			return nil, linkedin.MakeInternalServerError(err)
		}

		uID := s.jwt.GetUserID(*p.Authorization)
		if uID == "" {
			return nil, linkedin.MakeUnauthorized(errors.New("You must be logged in"))
		}
		_, err = database.GetUser(ctx, uID)
		if err == database.ErrUserNotFound {
			s.log.Println("Unable to get user account")
			return nil, linkedin.MakeInternalServerError(errors.New("Unable to find user account"))
		} else if err != nil {
			return nil, linkedin.MakeInternalServerError(err)
		}

		account := &database.LinkedinAccount{
			LinkedinEmail: gID,
			UserID:        uID,
		}
		err = database.CreateLinkedinAccount(ctx, account)
		if err != nil {
			return nil, linkedin.MakeInternalServerError(err)
		}
	default:
		s.log.Println("Bad Linkedin receive type")
		return nil, linkedin.MakeInternalServerError(errors.New("Invalid Linkedin connection type"))
	}

	return &linkedin.UserMedia{}, nil
}

func (s *LinkedinService) LinkedinRegister(ctx context.Context, grm *LinkedinRegisterMedia, OauthKey string) (*linkedin.UserMedia, error) {
	gr, err := database.GetLinkedinRegister(ctx, uuid.FromStringOrNil(OauthKey))
	if err == database.ErrLinkedinRegisterNotFound {
		return nil, linkedin.MakeNotFound(errors.New("Invalid registration key"))
	} else if err != nil {
		return nil, linkedin.MakeInternalServerError(err)
	}
	if gr.TimeCreated.Add(linkedinRegisterExpire).Before(time.Now()) {
		return nil, linkedin.MakeNotFound(errors.New("Invalid registration key"))
	}
	_, err = database.GetLinkedinAccount(ctx, gr.LinkedinEmail)
	if err == nil {
		return nil, linkedin.MakeForbidden(errors.New("This Linkedin account is already attached to an account"))
	} else if err != database.ErrLinkedinAccountNotFound {
		return nil, linkedin.MakeInternalServerError(err)
	}
	_, err = database.QueryUserEmail(ctx, grm.Email)
	if err == nil {
		return nil, linkedin.MakeForbidden(errors.New("This email is already in use" + " email " + grm.Email))
	} else if err != database.ErrUserNotFound {
		return nil, linkedin.MakeInternalServerError(err)
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

	captcha := ""

	newU := &models.User{
		FirstName:         grm.FirstName,
		LastName:          grm.LastName,
		Email:             grm.Email,
		VerifiedEmail:     true,
	}
	uID, err := createUser(ctx, newU, &captcha, ipAddr)
	if err == ErrInvalidRecaptcha {
		return nil, linkedin.MakeBadRequest(err)
	} else if err != nil {
		return nil, linkedin.MakeInternalServerError(err)
	}

	account := &database.LinkedinAccount{
		LinkedinEmail: gr.LinkedinEmail,
		UserID:        uID,
	}
	err = database.CreateLinkedinAccount(ctx, account)
	if err != nil {
		return nil, linkedin.MakeInternalServerError(err)
	}
	err = database.DeleteLinkedinRegister(ctx, uuid.FromStringOrNil(grm.OauthKey))
	if err != nil {
		s.log.Println("Unable to delete Linkedin registration progress")
	}

	sesToken, authToken, err := s.session.loginUser(ctx, *newU, remoteAddr, ctx.Value(RequestUserAgentKey).(string))
	if err != nil {
		return nil, linkedin.MakeInternalServerError(err)
	}

	token := "Bearer " + authToken

	return &linkedin.UserMedia{
		Email:         grm.Email,
		FirstName:     grm.FirstName,
		LastName:      grm.LastName,
		Authorization: token,
		XSession:      sesToken,
	}, nil
}
