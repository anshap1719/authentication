package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/anshap1719/authentication/controllers/gen/twitter"
	"github.com/anshap1719/authentication/database"
	"github.com/anshap1719/authentication/models"
	"github.com/anshap1719/authentication/utils/auth"
	. "github.com/anshap1719/authentication/utils/ctx"
	"github.com/globalsign/mgo"
	"github.com/gofrs/uuid"
	"github.com/mrjones/oauth"
	"log"
	"net"
	"os"
	"reflect"
	"strings"
	"time"
)

const (
	twitterAuthentication = iota
	twitterAttach
)

const (
	twitterConnectionExpire = 30 * time.Minute
	twitterRegisterExpire   = time.Hour
)

var twitterConf = oauth.NewConsumer(
	os.Getenv("TwitterKey"),
	os.Getenv("TwitterSecret"),
	oauth.ServiceProvider{
		RequestTokenUrl:   "https://api.twitter.com/oauth/request_token",
		AuthorizeTokenUrl: "https://api.twitter.com/oauth/authorize",
		AccessTokenUrl:    "https://api.twitter.com/oauth/access_token",
	})

// TwitterService implements the twitter resource.
type TwitterService struct {
	log     *log.Logger
	jwt     *auth.JWTSecurity
	session *SessionService
}

type TwitterRegisterMedia struct {
	OauthKey, FirstName, LastName, Email string
	TimeCreated                          time.Time
}

// NewTwitterService creates a twitter controller.
func NewTwitterService(log *log.Logger, jwt *auth.JWTSecurity, session *SessionService) twitter.Service {
	return &TwitterService{
		log:     log,
		jwt:     jwt,
		session: session,
	}
}

// Gets the URL the front-end should redirect the browser to in order to be
// authenticated with Twitter, and then register
func (s *TwitterService) RegisterURL(ctx context.Context, p *twitter.RegisterURLPayload) (res string, err error) {
	gc := &database.TwitterConnection{
		TimeCreated: time.Now(),
		Purpose:     twitterAuthentication,
	}
	state, err := database.CreateTwitterConnection(ctx, gc)
	if err != nil {
		fmt.Println("Error: ", err)
		return "", twitter.MakeInternalServerError(err)
	}

	tokenUrl := os.Getenv("ClientURL") + "/social/twitter?state=" + state.String()

	token, requestUrl, err := twitterConf.GetRequestTokenAndUrl(tokenUrl)
	if err != nil {
		return "", twitter.MakeInternalServerError(err)
	}

	if err := database.CreateTwitterToken(token.Token, *token); err != nil {
		return "", twitter.MakeInternalServerError(err)
	}

	return requestUrl, nil
}

// Attaches a Twitter account to an existing user account, returns the URL the
// browser should be redirected to
func (s *TwitterService) AttachToAccount(ctx context.Context, p *twitter.AttachToAccountPayload) (res string, err error) {
	gc := &database.TwitterConnection{
		TimeCreated: time.Now(),
		Purpose:     twitterAttach,
	}
	state, err := database.CreateTwitterConnection(ctx, gc)
	if err != nil {
		return "", twitter.MakeInternalServerError(err)
	}

	tokenUrl := os.Getenv("ClientURL") + "/social/twitter?state=" + state.String()

	token, requestUrl, err := twitterConf.GetRequestTokenAndUrl(tokenUrl)
	if err != nil {
		return "", twitter.MakeInternalServerError(err)
	}

	if err := database.CreateTwitterToken(token.Token, *token); err != nil {
		return "", twitter.MakeInternalServerError(err)
	}

	return requestUrl, nil
}

// Detaches a Twitter account from an existing user account.
func (s *TwitterService) DetachFromAccount(ctx context.Context, p *twitter.DetachFromAccountPayload) (err error) {
	uID := s.jwt.GetUserID(*p.Authorization)

	if getNumLoginMethods(ctx, uID) <= 1 {
		return twitter.MakeForbidden(errors.New("Cannot detach last login method"))
	}

	gID, err := database.QueryTwitterAccountUser(ctx, uID)
	if err == database.ErrTwitterAccountNotFound {
		return twitter.MakeNotFound(errors.New("User account is not connected to Twitter"))
	} else if err != nil {
		return twitter.MakeInternalServerError(err)
	}
	err = database.DeleteTwitterAccount(ctx, gID)
	if err != nil {
		return twitter.MakeInternalServerError(err)
	}
	return nil
}

// The endpoint that Twitter redirects the browser to after the user has
// authenticated
func (s *TwitterService) Receive(ctx context.Context, p *twitter.ReceivePayload) (res *twitter.UserMedia, err error) {
	state, err := uuid.FromString(*p.State)
	if err != nil {
		return nil, twitter.MakeBadRequest(errors.New("State UUID is invalid"))
	}

	gc, err := database.GetTwitterConnection(ctx, state)
	if err == database.ErrTwitterConnectionNotFound {
		return nil, twitter.MakeBadRequest(errors.New("Twitter connection must be created with other API methods"))
	} else if err != nil {
		return nil, twitter.MakeInternalServerError(err)
	}
	err = database.DeleteTwitterConnection(ctx, state)
	if err != nil {
		s.log.Println("Unable to delete Twitter connection")
	}
	if gc.TimeCreated.Add(twitterConnectionExpire).Before(time.Now()) {
		return nil, twitter.MakeBadRequest(errors.New("Twitter token expired. Please try again"))
	}

	code := p.OauthVerifier
	key := p.OauthToken

	token, err := database.GetTwitterToken(*key)
	if err == mgo.ErrNotFound {
		return nil, twitter.MakeBadRequest(err)
	} else if err != nil {
		return nil, twitter.MakeInternalServerError(err)
	}

	err = database.DeleteTwitterToken(*key)
	if err != nil {
		s.log.Println("Unable to delete Twitter connection")
	}

	accessToken, err := twitterConf.AuthorizeToken(token, *code)
	if err != nil {
		return nil, twitter.MakeInternalServerError(err)
	}

	client, err := twitterConf.MakeHttpClient(accessToken)
	if err != nil {
		return nil, twitter.MakeInternalServerError(err)
	}

	response, err := client.Get(
		"https://api.twitter.com/1.1/account/verify_credentials.json?include_entities=false&skip_status=true&include_email=true")
	if err != nil {
		return nil, twitter.MakeInternalServerError(err)
	}
	defer response.Body.Close()

	var twitterUser models.TwitterResponse

	if err := json.NewDecoder(response.Body).Decode(&twitterUser); err != nil {
		return nil, twitter.MakeInternalServerError(err)
	}

	gID := string(twitterUser.ID)

	switch gc.Purpose {
	case twitterAuthentication:
		account, err := database.GetTwitterAccount(ctx, gID)
		if err == database.ErrTwitterAccountNotFound {
			_, err := database.GetTwitterAccount(ctx, gID)
			if err == nil {
				return nil, twitter.MakeBadRequest(errors.New("This Twitter account is already attached to an account"))
			} else if err != database.ErrTwitterAccountNotFound {
				return nil, twitter.MakeInternalServerError(err)
			}

			gr := &database.TwitterRegister{
				TwitterID:   gID,
				TimeCreated: time.Now(),
			}
			regID, err := database.CreateTwitterRegister(ctx, gr)
			if err != nil {
				return nil, twitter.MakeInternalServerError(err)
			}

			grm := &TwitterRegisterMedia{
				OauthKey:  regID.String(),
				Email:     twitterUser.Email,
				FirstName: strings.Split(twitterUser.Name, " ")[0],
				LastName:  strings.Split(twitterUser.Name, " ")[1],
			}

			return s.TwitterRegister(ctx, grm, regID.String())
		} else if err != nil {
			return nil, twitter.MakeInternalServerError(err)
		}
		u, err := database.GetUser(ctx, account.UserID)
		if err != nil {
			return nil, twitter.MakeInternalServerError(err)
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
			return nil, twitter.MakeInternalServerError(err)
		}

		token := "Bearer " + authToken

		resp := &twitter.UserMedia{
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

	case twitterAttach:
		_, err := database.GetTwitterAccount(ctx, gID)
		if err == nil {
			return nil, twitter.MakeBadRequest(errors.New("This Twitter account is already attached to an account"))
		} else if err != database.ErrTwitterAccountNotFound {
			return nil, twitter.MakeInternalServerError(err)
		}

		uID := s.jwt.GetUserID(*p.Authorization)
		if uID == "" {
			return nil, twitter.MakeUnauthorized(errors.New("You must be logged in"))
		}
		_, err = database.GetUser(ctx, uID)
		if err == database.ErrUserNotFound {
			s.log.Println("Unable to get user account")
			return nil, twitter.MakeInternalServerError(errors.New("Unable to find user account"))
		} else if err != nil {
			return nil, twitter.MakeInternalServerError(err)
		}

		account := &database.TwitterAccount{
			ID:     gID,
			UserID: uID,
		}
		err = database.CreateTwitterAccount(ctx, account)
		if err != nil {
			return nil, twitter.MakeInternalServerError(err)
		}
	default:
		s.log.Println("Bad Twitter receive type")
		return nil, twitter.MakeInternalServerError(errors.New("Invalid Twitter connection type"))
	}

	return &twitter.UserMedia{}, nil
}

func (s *TwitterService) TwitterRegister(ctx context.Context, grm *TwitterRegisterMedia, OauthKey string) (*twitter.UserMedia, error) {
	gr, err := database.GetTwitterRegister(ctx, uuid.FromStringOrNil(grm.OauthKey))
	if err == database.ErrTwitterRegisterNotFound {
		return nil, twitter.MakeNotFound(errors.New("Invalid registration key"))
	} else if err != nil {
		return nil, twitter.MakeInternalServerError(err)
	}
	if gr.TimeCreated.Add(twitterRegisterExpire).Before(time.Now()) {
		return nil, twitter.MakeNotFound(errors.New("Invalid registration key"))
	}
	_, err = database.GetTwitterAccount(ctx, gr.TwitterID)
	if err == nil {
		return nil, twitter.MakeForbidden(errors.New("This Twitter account is already attached to an account"))
	} else if err != database.ErrTwitterAccountNotFound {
		return nil, twitter.MakeInternalServerError(err)
	}
	_, err = database.QueryUserEmail(ctx, grm.Email)
	if err == nil {
		return nil, twitter.MakeForbidden(errors.New("This email is already in use" + " email " + grm.Email))
	} else if err != database.ErrUserNotFound {
		return nil, twitter.MakeInternalServerError(err)
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

	newU := &models.User{
		FirstName:         grm.FirstName,
		LastName:          grm.LastName,
		Email:             grm.Email,
		VerifiedEmail:     true,
	}

	captcha := ""

	uID, err := createUser(ctx, newU, &captcha, ipAddr)
	if err == ErrInvalidRecaptcha {
		return nil, twitter.MakeBadRequest(err)
	} else if err != nil {
		return nil, twitter.MakeInternalServerError(err)
	}

	account := &database.TwitterAccount{
		ID:     gr.TwitterID,
		UserID: uID,
	}
	err = database.CreateTwitterAccount(ctx, account)
	if err != nil {
		return nil, twitter.MakeInternalServerError(err)
	}
	err = database.DeleteTwitterRegister(ctx, uuid.FromStringOrNil(grm.OauthKey))
	if err != nil {
		s.log.Println("Unable to delete Twitter registration progress")
	}

	sesToken, authToken, err := s.session.loginUser(ctx, *newU, remoteAddr, ctx.Value(RequestUserAgentKey).(string))
	if err != nil {
		return nil, twitter.MakeInternalServerError(err)
	}

	return &twitter.UserMedia{
		Email:         grm.Email,
		FirstName:     grm.FirstName,
		LastName:      grm.LastName,
		Authorization: authToken,
		XSession:      sesToken,
	}, nil
}
