package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/anshap1719/authentication/controllers/gen/instagram"
	"github.com/anshap1719/authentication/database"
	"github.com/anshap1719/authentication/models"
	"github.com/anshap1719/authentication/utils/auth"
	. "github.com/anshap1719/authentication/utils/ctx"
	"github.com/gofrs/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/oauth2"
	instagramOauth "golang.org/x/oauth2/instagram"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"
)

// InstagramService implements the instagram resource.
type InstagramService struct {
	log     *log.Logger
	jwt     *auth.JWTSecurity
	session *SessionService
}

type InstagramRegisterMedia struct {
	AccessToken *string `json:"access_token,omitempty"`
	// Instagram user
	User *InstagramUserMedia `json:"user,omitempty"`
	// A merge token for merging into an account
	OauthKey      *string `json:"oauth_key,omitempty"`
	Authorization *string `json:"authorization,omitempty"`
	XSession      *string `json:"x_session,omitempty"`
}
type InstagramUserMedia struct {
	// Instagram id of connected account
	ID *string `json:"id,omitempty"`
	// Instagram username of connected account
	Username *string `json:"username,omitempty"`
	// Full name of the user
	FullName *string `json:"full_name,omitempty"`
	// Instagram DP of the user
	ProfilePicture *string `json:"profile_picture,omitempty"`
}

const (
	instagramAuthentication = iota
	instagramAttach
)

const (
	instagramConnectionExpire = 30 * time.Minute
	instagramRegisterExpire   = time.Hour
)

var instagramConf = &oauth2.Config{
	ClientID:     os.Getenv("InstagramID"),
	ClientSecret: os.Getenv("InstagramSecret"),
	Scopes: []string{
		"basic",
	},
	Endpoint: instagramOauth.Endpoint,
}

// NewInstagramService creates a instagram controller.
func NewInstagramService(log *log.Logger, jwt *auth.JWTSecurity, session *SessionService) instagram.Service {
	return &InstagramService{
		log:     log,
		jwt:     jwt,
		session: session,
	}
}

// Gets the URL the front-end should redirect the browser to in order to be
// authenticated with Instagram, and then register
func (s *InstagramService) RegisterURL(ctx context.Context, p *instagram.RegisterURLPayload) (res string, err error) {
	gc := &database.InstagramConnection{
		TimeCreated: time.Now(),
		Purpose:     instagramAuthentication,
	}

	state, err := database.CreateInstagramConnection(ctx, gc)
	if err != nil {
		return "", instagram.MakeInternalServerError(err)
	}

	instagramConf.RedirectURL = *p.RedirectURL
	return instagramConf.AuthCodeURL(state.String()), nil
}

// Attaches a Instagram account to an existing user account, returns the URL
// the browser should be redirected to
func (s *InstagramService) AttachToAccount(ctx context.Context, p *instagram.AttachToAccountPayload) (res string, err error) {
	gc := &database.InstagramConnection{
		TimeCreated: time.Now(),
		Purpose:     instagramAttach,
	}
	state, err := database.CreateInstagramConnection(ctx, gc)
	if err != nil {
		return "", instagram.MakeInternalServerError(err)
	}

	instagramConf.RedirectURL = *p.RedirectURL
	return instagramConf.AuthCodeURL(state.String()), nil
}

// Detaches a Instagram account from an existing user account.
func (s *InstagramService) DetachFromAccount(ctx context.Context, p *instagram.DetachFromAccountPayload) (err error) {
	uID := s.jwt.GetUserID(*p.Authorization)

	if getNumLoginMethods(ctx, uID) <= 1 {
		return instagram.MakeForbidden(errors.New("Cannot detach last login method"))
	}

	gID, err := database.QueryInstagramAccountUser(ctx, uID)
	if err == database.ErrInstagramAccountNotFound {
		return instagram.MakeNotFound(errors.New("User account is not connected to Instagram"))
	} else if err != nil {
		return instagram.MakeInternalServerError(err)
	}
	err = database.DeleteInstagramAccount(ctx, gID)
	if err != nil {
		return instagram.MakeInternalServerError(err)
	}
	return nil
}

// The endpoint that Instagram redirects the browser to after the user has
// authenticated
func (s *InstagramService) Receive(ctx context.Context, p *instagram.ReceivePayload) (res *instagram.UserMedia, err error) {
	gc, err := database.GetInstagramConnection(ctx, uuid.FromStringOrNil(*p.State))
	if err == database.ErrInstagramConnectionNotFound {
		return nil, instagram.MakeBadRequest(errors.New("Instagram connection must be created with other API methods"))
	} else if err != nil {
		fmt.Println(err)
		return nil, instagram.MakeInternalServerError(err)
	}

	err = database.DeleteInstagramConnection(ctx, uuid.FromStringOrNil(*p.State))
	if err != nil {
		s.log.Println("Unable to delete Instagram connection")
	}

	if gc.TimeCreated.Add(instagramConnectionExpire).Before(time.Now()) {
		return nil, instagram.MakeBadRequest(errors.New("Instagram token expired. Please try again"))
	}

	instagramConf.RedirectURL = *p.RedirectURL
	token, err := instagramConf.Exchange(ctx, *p.Code)
	if err != nil {
		return nil, instagram.MakeBadRequest(err)
	}

	resp, err := http.Get("https://api.instagram.com/v1/users/self/?access_token=" + token.AccessToken)
	if err != nil {
		fmt.Println(err)
		return nil, instagram.MakeInternalServerError(errors.New("Unable to get user data from instagram"))
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, instagram.MakeBadRequest(errors.New("Invalid Instagram data"))
	}

	instagramUser := &InstagramUser{}

	var rawData map[string]interface{}

	err = json.NewDecoder(resp.Body).Decode(&rawData)
	if err != nil {
		return nil, instagram.MakeInternalServerError(err)
	}

	data := rawData["data"].(map[string]interface{})

	instagramUser.User = InstagramUserData{
		ID:             data["id"].(string),
		Username:       data["username"].(string),
		FullName:       data["full_name"].(string),
		ProfilePicture: data["profile_picture"].(string),
	}

	gID := instagramUser.GetID()
	if gID == "" {
		return nil, instagram.MakeBadRequest(errors.New("Unable to get Instagram user ID"))
	}

	switch gc.Purpose {
	case instagramAuthentication:
		account, err := database.GetInstagramAccount(ctx, gID)
		if err == database.ErrInstagramAccountNotFound {
			gr := &database.InstagramRegister{
				InstagramID: gID,
				TimeCreated: time.Now(),
			}
			regID, err := database.CreateInstagramRegister(ctx, gr)
			if err != nil {
				return nil, instagram.MakeInternalServerError(err)
			}

			key := regID.String()

			grm := &InstagramRegisterMedia{
				OauthKey: &key,
				User: &InstagramUserMedia{
					FullName:       &instagramUser.User.FullName,
					ID:             &instagramUser.User.ID,
					ProfilePicture: &instagramUser.User.ProfilePicture,
					Username:       &instagramUser.User.Username,
				},
			}

			return s.InstagramRegister(ctx, gr, grm, rawData)
		} else if err != nil {
			return nil, instagram.MakeInternalServerError(err)
		}
		u, err := database.GetUser(ctx, account.UserID)
		if err != nil {
			return nil, instagram.MakeInternalServerError(err)
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
			return nil, instagram.MakeInternalServerError(err)
		}

		token := "Bearer " + authToken

		res = database.UserToInstagramUser(u)
		res.Authorization = token
		res.XSession = sesToken

		return res, nil
	case instagramAttach:
		_, err := database.GetInstagramAccount(ctx, gID)
		if err == nil {
			return nil, instagram.MakeBadRequest(errors.New("This Instagram account is already attached to an account"))
		} else if err != database.ErrInstagramAccountNotFound {
			return nil, instagram.MakeInternalServerError(err)
		}

		if p.Authorization == nil {
			return nil, instagram.MakeUnauthorized(errors.New("You must be logged in"))
		}

		uID := s.jwt.GetUserID(*p.Authorization)
		if uID == "" {
			return nil, instagram.MakeUnauthorized(errors.New("You must be logged in"))
		}
		u, err := database.GetUser(ctx, uID)
		if err == database.ErrUserNotFound {
			s.log.Println("Unable to get user account")
			return nil, instagram.MakeInternalServerError(errors.New("Unable to find user account"))
		} else if err != nil {
			return nil, instagram.MakeInternalServerError(err)
		}

		u.ID, _ = primitive.ObjectIDFromHex(uID)

		if err := database.UpdateUser(ctx, u); err != nil {
			return nil, instagram.MakeInternalServerError(errors.New("Unable to update user instagram data: " + err.Error()))
		}

		account := &database.InstagramAccount{
			ID:                gID,
			UserID:            uID,
			InstagramUsername: instagramUser.User.Username,
			RawData:           rawData,
		}
		err = database.CreateInstagramAccount(ctx, account)
		if err != nil {
			return nil, instagram.MakeInternalServerError(err)
		}

		return database.UserToInstagramUser(u), nil
	default:
		s.log.Println("Bad Receive Type")
		return nil, instagram.MakeInternalServerError(errors.New("Invalid Instagram connection type"))
	}

	return nil, nil
}

type InstagramUser struct {
	AccessToken string            `json:"access_token,omitempty"`
	User        InstagramUserData `json:"user,omitempty"`
}

type InstagramUserData struct {
	ID             string `json:"id,omitempty"`
	Username       string `json:"username,omitempty"`
	FullName       string `json:"full_name,omitempty"`
	ProfilePicture string `json:"profile_picture,omitempty"`
}

func (g *InstagramUser) GetID() string {
	return g.User.ID
}

func (s *InstagramService) InstagramRegister(ctx context.Context, gr *database.InstagramRegister, grm *InstagramRegisterMedia, rawData map[string]interface{}) (res *instagram.UserMedia, err error) {
	if gr.TimeCreated.Add(instagramRegisterExpire).Before(time.Now()) {
		return nil, instagram.MakeNotFound(errors.New("Invalid registration key"))
	}
	_, err = database.GetInstagramAccount(ctx, gr.InstagramID)
	if err == nil {
		return nil, instagram.MakeForbidden(errors.New("This Instagram account is already attached to an account"))
	} else if err != database.ErrInstagramAccountNotFound {
		return nil, instagram.MakeInternalServerError(err)
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

	newU := userFromInstagramRegisterMedia(grm)
	uID, err := createUser(ctx, newU, nil, ipAddr)
	if err == ErrInvalidRecaptcha {
		return nil, instagram.MakeBadRequest(err)
	} else if err != nil {
		return nil, instagram.MakeInternalServerError(err)
	}

	account := &database.InstagramAccount{
		ID:                gr.InstagramID,
		UserID:            uID,
		InstagramUsername: *grm.User.Username,
		RawData:           rawData,
	}

	err = database.CreateInstagramAccount(ctx, account)
	if err != nil {
		return nil, instagram.MakeInternalServerError(err)
	}
	err = database.DeleteInstagramRegister(ctx, uuid.FromStringOrNil(*grm.OauthKey))
	if err != nil {
		s.log.Println("Unable to delete Instagram registration progress")
	}

	sesToken, authToken, err := s.session.loginUser(ctx, *newU, remoteAddr, ctx.Value(RequestUserAgentKey).(string))
	if err != nil {
		return nil, instagram.MakeInternalServerError(err)
	}

	token := "Bearer " + authToken

	res = database.UserToInstagramUser(newU)

	res.Authorization = token
	res.XSession = sesToken

	return res, nil
}

func userFromInstagramRegisterMedia(gen *InstagramRegisterMedia) *models.User {
	names := strings.SplitN(*gen.User.FullName, " ", -1)

	var first, last string

	if len(names) > 1 {
		first = names[0]
		last = names[1]
	} else {
		first = *gen.User.FullName
		last = ""
	}
	s := &models.User{
		FirstName:         first,
		LastName:          last,
	}
	return s
}
