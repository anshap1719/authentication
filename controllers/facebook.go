package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/anshap1719/authentication/controllers/gen/facebook"
	"github.com/anshap1719/authentication/database"
	"github.com/anshap1719/authentication/models"
	"github.com/anshap1719/authentication/utils/auth"
	. "github.com/anshap1719/authentication/utils/ctx"
	"github.com/gofrs/uuid"
	"golang.org/x/oauth2"
	"log"
	"net"
	"os"
	"reflect"
	"time"
)

// FacebookController implements the facebook resource.
type FacebookService struct {
	log     *log.Logger
	jwt     *auth.JWTSecurity
	session *SessionService
}

const (
	facebookAuthentication = iota
	facebookAttach
)

const (
	facebookConnectionExpire = 30 * time.Minute
	facebookRegisterExpire   = time.Hour
)

var facebookConf = &oauth2.Config{
	ClientID:     os.Getenv("FacebookID"),
	ClientSecret: os.Getenv("FacebookSecret"),
	Scopes: []string{
		"public_profile",
		"email",
	},
	Endpoint: oauth2.Endpoint{
		AuthURL:  "https://www.facebook.com/v2.12/dialog/oauth",
		TokenURL: "https://graph.facebook.com/v2.12/oauth/access_token",
	},
	RedirectURL: os.Getenv("ClientURL") + "/social/facebook",
}

// NewFacebookController creates a facebook controller.
func NewFacebookService(log *log.Logger, jwt *auth.JWTSecurity, session *SessionService) facebook.Service {
	return &FacebookService{
		log:     log,
		jwt:     jwt,
		session: session,
	}
}

type FacebookRegisterMedia struct {
	OauthKey, FirstName, LastName, Email string
	TimeCreated                          time.Time
}

// Gets the URL the front-end should redirect the browser to in order to be
// authenticated with Facebook, and then register
func (s *FacebookService) RegisterURL(ctx context.Context, p *facebook.RegisterURLPayload) (res string, err error) {
	gc := &database.FacebookConnection{
		TimeCreated: time.Now(),
		Purpose:     facebookAuthentication,
	}

	state, err := database.CreateFacebookConnection(ctx, gc)
	if err != nil {
		s.log.Println(err)
		return "", facebook.MakeInternalServerError(err)
	}

	return facebookConf.AuthCodeURL(state.String()), nil
}

// Attaches a Facebook account to an existing user account, returns the URL the
// browser should be redirected to
func (s *FacebookService) AttachToAccount(ctx context.Context, p *facebook.AttachToAccountPayload) (res string, err error) {
	gc := &database.FacebookConnection{
		TimeCreated: time.Now(),
		Purpose:     facebookAttach,
	}
	state, err := database.CreateFacebookConnection(ctx, gc)
	if err != nil {
		return "", err
	}

	return facebookConf.AuthCodeURL(state.String()), nil
}

// Detaches a Facebook account from an existing user account.
func (s *FacebookService) DetachFromAccount(ctx context.Context, p *facebook.DetachFromAccountPayload) (err error) {
	uID := s.jwt.GetUserID(*p.Authorization)

	if getNumLoginMethods(ctx, uID) <= 1 {
		return facebook.MakeForbidden(errors.New("Cannot detach last login method"))
	}

	gID, err := database.QueryFacebookAccountUser(ctx, uID)
	if err == database.ErrFacebookAccountNotFound {
		return facebook.MakeNotFound(errors.New("User account is not connected to Facebook"))
	} else if err != nil {
		return facebook.MakeInternalServerError(err)
	}
	err = database.DeleteFacebookAccount(ctx, gID)
	if err != nil {
		return facebook.MakeInternalServerError(err)
	}

	return nil
}

// The endpoint that Facebook redirects the browser to after the user has
// authenticated
func (s *FacebookService) Receive(ctx context.Context, p *facebook.ReceivePayload) (res *facebook.UserMedia, err error) {
	gc, err := database.GetFacebookConnection(ctx, uuid.FromStringOrNil(*p.State))
	if err == database.ErrFacebookConnectionNotFound {
		return nil, facebook.MakeBadRequest(errors.New("Facebook connection must be created with other API methods"))
	} else if err != nil {
		return nil, facebook.MakeInternalServerError(err)
	}
	err = database.DeleteFacebookConnection(ctx, uuid.FromStringOrNil(*p.State))
	if err != nil {
		log.Printf("Unable to delete Facebook connection, state=%s", *p.State)
	}
	if gc.TimeCreated.Add(facebookConnectionExpire).Before(time.Now()) {
		return nil, facebook.MakeBadRequest(errors.New("Facebook token expired. Please try again"))
	}

	token, err := facebookConf.Exchange(ctx, *p.Code)
	if err != nil {
		return nil, facebook.MakeBadRequest(err)
	}

	tokenClient := facebookConf.Client(ctx, token)
	resp, err := tokenClient.Get("https://graph.facebook.com/v2.12/me?fields=id,first_name,last_name,email")
	if err != nil {
		return nil, facebook.MakeInternalServerError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, facebook.MakeBadRequest(errors.New("Invalid Facebook data"))
	}
	facebookUser := &FacebookUser{}
	err = json.NewDecoder(resp.Body).Decode(facebookUser)
	if err != nil {
		return nil, facebook.MakeInternalServerError(err)
	}

	gID := facebookUser.GetID()
	if gID == "" {
		return nil, facebook.MakeBadRequest(errors.New("Unable to get Facebook user ID"))
	}

	switch gc.Purpose {
	case facebookAuthentication:
		account, err := database.GetFacebookAccount(ctx, gID)
		if err == database.ErrFacebookAccountNotFound {
			_, err := database.GetFacebookAccount(ctx, gID)
			if err == nil {
				return nil, facebook.MakeBadRequest(errors.New("This Facebook account is already attached to an account"))
			} else if err != database.ErrFacebookAccountNotFound {
				return nil, facebook.MakeInternalServerError(err)
			}

			gr := &database.FacebookRegister{
				FacebookID:  gID,
				TimeCreated: time.Now(),
			}
			regID, err := database.CreateFacebookRegister(ctx, gr)
			if err != nil {
				return nil, facebook.MakeInternalServerError(err)
			}

			grm := &FacebookRegisterMedia{
				OauthKey:  regID.String(),
				Email:     facebookUser.Email,
				FirstName: facebookUser.FirstName,
				LastName:  facebookUser.LastName,
			}

			return s.FacebookRegister(ctx, grm, regID.String())
		} else if err != nil {
			return nil, facebook.MakeInternalServerError(err)
		}
		u, err := database.GetUser(ctx, account.UserID)
		if err != nil {
			return nil, facebook.MakeInternalServerError(err)
		}

		fmt.Println(ctx, *u, "", ctx.Value(RequestUserAgentKey).(string))
		if err != nil {
			return nil, facebook.MakeInternalServerError(err)
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
			return nil, facebook.MakeInternalServerError(err)
		}

		token := "Bearer " + authToken

		resp := &facebook.UserMedia{
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
	case facebookAttach:
		_, err := database.GetFacebookAccount(ctx, gID)
		if err == nil {
			return nil, facebook.MakeBadRequest(errors.New("This Facebook account is already attached to an account"))
		} else if err != database.ErrFacebookAccountNotFound {
			return nil, facebook.MakeInternalServerError(err)
		}

		uID := s.jwt.GetUserID(*p.Authorization)
		if uID == "" {
			return nil, facebook.MakeUnauthorized(errors.New("You must be logged in"))
		}
		_, err = database.GetUser(ctx, uID)
		if err == database.ErrUserNotFound {
			s.log.Println("Unable to get user account")
			return nil, facebook.MakeInternalServerError(errors.New("Unable to find user account"))
		} else if err != nil {
			return nil, facebook.MakeInternalServerError(err)
		}

		account := &database.FacebookAccount{
			ID:     gID,
			UserID: uID,
		}
		err = database.CreateFacebookAccount(ctx, account)
		if err != nil {
			return nil, facebook.MakeInternalServerError(err)
		}
	default:
		s.log.Fatal("Bad Facebook receive type")
		return nil, facebook.MakeInternalServerError(errors.New("Invalid Facebook connection type"))
	}

	return nil, nil
}

type FacebookUser struct {
	ID        string `json:"id,omitempty"`
	Email     string `json:"email,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

func (g *FacebookUser) GetID() string {
	return g.ID
}

func (s *FacebookService) FacebookRegister(ctx context.Context, grm *FacebookRegisterMedia, OauthKey string) (*facebook.UserMedia, error) {
	gr, err := database.GetFacebookRegister(ctx, uuid.FromStringOrNil(grm.OauthKey))
	if err == database.ErrFacebookRegisterNotFound {
		return nil, facebook.MakeNotFound(errors.New("Invalid registration key"))
	} else if err != nil {
		s.log.Println(err)
		return nil, facebook.MakeInternalServerError(err)
	}
	if gr.TimeCreated.Add(facebookRegisterExpire).Before(time.Now()) {
		return nil, facebook.MakeNotFound(errors.New("Invalid registration key"))
	}
	_, err = database.GetFacebookAccount(ctx, gr.FacebookID)
	if err == nil {
		return nil, facebook.MakeForbidden(errors.New("This Facebook account is already attached to an account"))
	} else if err != database.ErrFacebookAccountNotFound {
		s.log.Println(err)
		return nil, facebook.MakeInternalServerError(err)
	}
	_, err = database.QueryUserEmail(ctx, grm.Email)
	if err == nil {
		return nil, facebook.MakeForbidden(errors.New("This email is already in use " + "email " + grm.Email))
	} else if err != database.ErrUserNotFound {
		s.log.Println(err)
		return nil, facebook.MakeInternalServerError(err)
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
		return nil, facebook.MakeBadRequest(err)
	} else if err != nil {
		s.log.Println(err)
		return nil, facebook.MakeInternalServerError(err)
	}

	account := &database.FacebookAccount{
		ID:     gr.FacebookID,
		UserID: uID,
	}
	err = database.CreateFacebookAccount(ctx, account)
	if err != nil {
		s.log.Println(err)
		return nil, facebook.MakeInternalServerError(err)
	}
	err = database.DeleteFacebookRegister(ctx, uuid.FromStringOrNil(grm.OauthKey))
	if err != nil {
		s.log.Println("Unable to delete Facebook registration progress key")
	}

	sesToken, authToken, err := s.session.loginUser(ctx, *newU, remoteAddr, ctx.Value(RequestUserAgentKey).(string))
	if err != nil {
		return nil, facebook.MakeInternalServerError(err)
	}

	token := "Bearer " + authToken

	return &facebook.UserMedia{
		Email:         grm.Email,
		FirstName:     grm.FirstName,
		LastName:      grm.LastName,
		Authorization: token,
		XSession:      sesToken,
	}, nil
}
