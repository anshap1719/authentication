package controllers

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/anshap1719/authentication/controllers/gen/user"
	"github.com/anshap1719/authentication/database"
	"github.com/anshap1719/authentication/models"
	"github.com/anshap1719/authentication/utils/auth"
	"github.com/anshap1719/authentication/utils/email"
	"github.com/anshap1719/authentication/utils/sms"
	"github.com/globalsign/mgo"
	"github.com/simukti/emailcheck"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"google.golang.org/appengine/urlfetch"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const emailValidateExpiration = 7 * 24 * time.Hour

var ErrInvalidRecaptcha = errors.New("Invalid recaptcha response")

// UsersService implements the user resource.
type UsersService struct {
	log     *log.Logger
	jwt     *auth.JWTSecurity
	session *SessionService
}

// NewUsersService creates a user controller.
func NewUsersService(log *log.Logger, jwt *auth.JWTSecurity, session *SessionService) user.Service {
	return &UsersService{
		log:     log,
		jwt:     jwt,
		session: session,
	}
}

// Update a user
func (s *UsersService) UpdateUser(ctx context.Context, p *user.UserUpdateParams) (res *user.UserMedia, retErr error) {
	uID := s.jwt.GetUserID(*p.Authorization)
	u, err := database.GetUser(ctx, uID)
	if err != nil {
		return nil, user.MakeInternalServerError(err)
	}

	emailChanged := false
	oldEmail := u.Email

	oldAdmin := u.IsAdmin
	if p.IsAdmin != nil && *p.IsAdmin != oldAdmin && s.jwt.IsAdmin(*p.Authorization) {
		return nil, user.MakeForbidden(errors.New("you are not allowed to modify a user's admin status"))
	}

	if p.Email != nil {
		if emailcheck.IsDisposableEmail(*p.Email) {
			return nil, user.MakeForbidden(errors.New("Disposable email not allowed"))
		}
		_, err = database.QueryUserEmail(ctx, *p.Email)
		if err == nil {
			return nil, user.MakeForbidden(errors.New("Email is already in use"))
		} else if err != database.ErrUserNotFound {
			return nil, user.MakeInternalServerError(err)
		}
		emailChanged = true
		if u.VerifiedEmail {
			u.ChangingEmail = *p.Email
		} else {
			u.Email = *p.Email
		}
		p.Email = nil
	}

	if emailChanged {
		ev := &database.EmailVerification{
			UserID:      uID,
			TimeExpires: time.Now().Add(7 * 24 * time.Hour),
		}
		if u.VerifiedEmail {
			ev.Email = u.ChangingEmail
		} else {
			ev.Email = u.Email
		}
		eID, err := generateEmailID(ev.Email)
		if err != nil {
			return nil, user.MakeInternalServerError(err)
		}
		ev.ID = eID
		err = database.CreateEmailVerification(ctx, ev)
		if err != nil {
			fmt.Println("error 2", err)
			return nil, user.MakeInternalServerError(err)
		}

		redirectURl := os.Getenv("ClientURL") + "/influencer/verify-email/" + eID
		toName := u.FirstName + " " + u.LastName
		toMail := ev.Email

		if err := email.SendVerificationEmail(toMail, toName, redirectURl); err != nil {
			return nil, user.MakeInternalServerError(err)
		}

		if !u.VerifiedEmail {
			pl, err := database.GetPasswordLogin(ctx, oldEmail)
			if err == nil {
				pl.Email = u.Email
				err = database.UpdatePasswordLogin(ctx, pl)
				if err != nil {
					fmt.Println("error 1", err)
					return nil, user.MakeInternalServerError(err)
				}
				err = database.DeletePasswordLogin(ctx, oldEmail)
				if err != nil {
					return nil, user.MakeInternalServerError(err)
				}
			} else if err != database.ErrPasswordLoginNotFound {
				return nil, user.MakeInternalServerError(err)
			}
		}
	}

	s.updateUserFields(u, p)

	err = database.UpdateUser(ctx, u)
	if err != nil {
		return nil, user.MakeInternalServerError(err)
	}

	return &user.UserMedia{
		ID:                u.ID.Hex(),
		FirstName:         u.FirstName,
		LastName:          u.LastName,
		Email:             u.Email,
		VerifiedEmail:     u.VerifiedEmail,
		IsAdmin:           &u.IsAdmin,
		Authorization:     *p.Authorization,
		XSession:          *p.XSession,
	}, nil
}

// Returns whether Oauth is attached or not
func (s *UsersService) GetAuths(ctx context.Context, p *user.GetAuthsPayload) (res *user.AuthStatusMedia, retErr error) {
	var uID string
	var err error

	if p.UserID == nil || *p.UserID == "" {
		return nil, user.MakeBadRequest(errors.New("User ID must be a non-empty string"))
	} else if p.UserID != nil && s.jwt.IsAdmin(*p.Authorization) {
		uID = *p.UserID
	} else {
		uID = s.jwt.GetUserID(*p.Authorization)
		if uID == "" {
			return nil, user.MakeUnauthorized(errors.New("User ID was not recognised."))
		}
	}

	AST := &user.AuthStatusMedia{}

	_, err = database.QueryPasswordLoginFromID(ctx, uID)
	if err != nil {
		if err != database.ErrPasswordLoginNotFound {
			return nil, user.MakeInternalServerError(err)
		}
	} else {
		AST.Standard = true
	}

	_, err = database.QueryGoogleAccountUser(ctx, uID)
	if err != nil {
		if err != database.ErrGoogleAccountNotFound {
			return nil, user.MakeInternalServerError(err)
		}
	} else {
		AST.Google = true
	}

	_, err = database.QueryFacebookAccountUser(ctx, uID)
	if err != nil {
		if err != database.ErrFacebookAccountNotFound {
			return nil, user.MakeInternalServerError(err)
		}
	} else {
		AST.Facebook = true
	}

	_, err = database.QueryLinkedinAccountUser(ctx, uID)
	if err != nil {
		if err != database.ErrLinkedinAccountNotFound {
			return nil, user.MakeInternalServerError(err)
		}
	} else {
		AST.Linkedin = true
	}

	_, err = database.QueryTwitterAccountUser(ctx, uID)
	if err != nil {
		if err != database.ErrTwitterAccountNotFound {
			return nil, user.MakeInternalServerError(err)
		}
	} else {
		AST.Twitter = true
	}

	_, err = database.QueryInstagramAccountUser(ctx, uID)
	if err != nil {
		if err != database.ErrInstagramAccountNotFound {
			return nil, user.MakeInternalServerError(err)
		}
	} else {
		AST.Instagram = true
	}

	return AST, nil
}

func (s *UsersService) GetUser(ctx context.Context, p *user.GetUserPayload) (res *user.UserMedia, retErr error) {
	var userID string
	var err error

	uID := s.jwt.GetUserID(*p.Authorization)

	if userID == "" {
		userID = uID
		if uID == "" {
			return nil, user.MakeUnauthorized(errors.New("Must be logged in to view own profile"))
		}
	}

	u, err := database.GetUser(ctx, userID)
	if err == database.ErrUserNotFound {
		return nil, user.MakeNotFound(err)
	} else if err != nil {
		return nil, user.MakeInternalServerError(err)
	}

	resp := database.UserToUser(u)

	return resp, nil
}

// Disable a user's account
func (s *UsersService) Deactivate(ctx context.Context, p *user.DeactivatePayload) (retErr error) {
	var uID string

	if s.jwt.IsAdmin(*p.Authorization) {
		uID = *p.ID
	} else {
		uID = s.jwt.GetUserID(*p.Authorization)
	}

	_, err := database.GetUser(ctx, uID)
	if err == mgo.ErrNotFound {
		return user.MakeInternalServerError(err)
	} else if err != nil {
		return user.MakeInternalServerError(err)
	}

	type access struct {
		query    func(context.Context, string) (string, error)
		notFound error
		deletion func(context.Context, string) error
	}

	getAccountItems := []access{
		{
			query:    database.QueryGoogleAccountUser,
			notFound: database.ErrGoogleAccountNotFound,
			deletion: database.DeleteGoogleAccount,
		},
		{
			query:    database.QueryFacebookAccountUser,
			notFound: database.ErrFacebookAccountNotFound,
			deletion: database.DeleteFacebookAccount,
		},
		{
			query:    database.QueryTwitterAccountUser,
			notFound: database.ErrTwitterAccountNotFound,
			deletion: database.DeleteTwitterAccount,
		},
		{
			query:    database.QueryLinkedinAccountUser,
			notFound: database.ErrLinkedinAccountNotFound,
			deletion: database.DeleteLinkedinAccount,
		},
		{
			query:    database.QueryPasswordLoginFromID,
			notFound: database.ErrPasswordLoginNotFound,
			deletion: database.DeletePasswordLogin,
		},
	}

	for _, v := range getAccountItems {
		k, err := v.query(ctx, uID)
		if err == nil {
			err = v.deletion(ctx, k)
			if err != nil {
				return user.MakeInternalServerError(err)
			}
		} else if err != v.notFound {
			return user.MakeInternalServerError(err)
		}
	}

	// @TODO: Send Notification Via Email

	_ = struct {
		UserAbout string
		Type      string
	}{
		UserAbout: uID,
		Type:      "user-disabled",
	}

	//toName := user.FirstName + " " + user.LastName
	//toMail := user.Email
	//textContent := "Your account has been disabled"
	//htmlContent := "Your account has been disabled"
	//subject := "Your account has been disabled"
	//
	//if err := email.SendMail(subject, toName, toMail, textContent, htmlContent); err != nil {
	//	return ctx.InternalServerError(err)
	//}

	return nil
}

// Validates an email address, designed to be called by users directly in their
// browser
func (s *UsersService) ValidateEmail(ctx context.Context, p *user.ValidateEmailPayload) (err error) {
	ev, err := database.GetEmailVerification(ctx, *p.ValidateID)
	if err == database.ErrEmailVerificationNotFound {
		return user.MakeNotFound(errors.New("Invalid verification code. Please login and request a new verification email."))
	} else if err != nil {
		return user.MakeInternalServerError(err)
	}

	if time.Now().After(ev.TimeExpires) {
		if err := database.DeleteEmailVerification(ctx, *p.ValidateID); err != nil {
			return err
		}
		return user.MakeNotFound(errors.New("Verification Code Has Expired. Please login and request a new verification email."))
	}

	u, err := database.GetUser(ctx, ev.UserID)
	if err != nil {
		return user.MakeInternalServerError(err)
	}

	if !u.VerifiedEmail {
		if u.Email != ev.Email {
			return user.MakeNotFound(errors.New("Email is not the same as the one currently attached to this account"))
		}
		u.VerifiedEmail = true
		u.ChangingEmail = u.Email
	} else {
		if u.ChangingEmail != ev.Email {
			return user.MakeNotFound(errors.New("Email is not the same as the one currently attached to this account"))
		}

		pl, err := database.GetPasswordLogin(ctx, u.Email)
		if err == nil {
			pl.Email = u.ChangingEmail
			err = database.UpdatePasswordLogin(ctx, pl)
			if err != nil {
				return user.MakeInternalServerError(err)
			}
			err = database.DeletePasswordLogin(ctx, u.Email)
			if err != nil {
				return user.MakeInternalServerError(err)
			}
		} else if err != database.ErrPasswordLoginNotFound {
			return user.MakeInternalServerError(err)
		}

		u.Email = u.ChangingEmail
	}

	err = database.UpdateUser(ctx, u)
	if err != nil {
		return user.MakeInternalServerError(err)
	}

	if err := database.DeleteEmailVerification(ctx, *p.ValidateID); err != nil {
		return err
	}

	return nil
}

// Resends a verify email for the current user, also invalidates the link on
// the previously send email verification
func (s *UsersService) ResendVerifyEmail(ctx context.Context, p *user.ResendVerifyEmailPayload) (err error) {
	uID := s.jwt.GetUserID(*p.Authorization)

	u, err := database.GetUser(ctx, uID)
	if err != nil {
		return user.MakeInternalServerError(err)
	}

	if u.VerifiedEmail && (u.ChangingEmail == "" || u.ChangingEmail == u.Email) {
		return user.MakeNotFound(errors.New("No email needs verifying currently"))
	}

	oldEv, err := database.QueryEmailVerificationByUserID(ctx, uID)
	if err == nil {
		if time.Now().Before(oldEv.TimeExpires) && oldEv.TimeExpires.Sub(time.Now()) < time.Minute*30 {
			return user.MakeBadRequest(errors.New("You cannot request another email within 30 minutes of your last request"))
		}
		database.DeleteEmailVerification(ctx, oldEv.ID)
	} else if err != database.ErrEmailVerificationNotFound {
		return user.MakeInternalServerError(err)
	}

	eID, err := generateEmailID(u.Email)
	if err != nil {
		return user.MakeInternalServerError(err)
	}

	ev := &database.EmailVerification{
		ID:          eID,
		UserID:      uID,
		TimeExpires: time.Now().Add(emailValidateExpiration),
		Email:       u.Email,
	}
	if u.VerifiedEmail && u.ChangingEmail != u.Email && u.ChangingEmail != "" {
		ev.Email = u.ChangingEmail
	}
	err = database.CreateEmailVerification(ctx, ev)
	if err != nil {
		return user.MakeInternalServerError(err)
	}

	toName := u.FirstName + " " + u.LastName
	toMail := u.Email

	if err := email.SendVerificationEmail(strings.ToLower(toMail), toName, os.Getenv("ClientURL")+"/influencer/verify-email/"+eID); err != nil {
		return user.MakeInternalServerError(err)
	}

	return nil
}

func (s *UsersService) UpdatePhone(ctx context.Context, p *user.UpdatePhonePayload) error {
	uID := s.jwt.GetUserID(*p.Authorization)
	if uID == "" {
		return user.MakeUnauthorized(errors.New("unable to verify login status"))
	}

	exists := CheckPhoneExists(*p.Phone)

	if exists {
		return user.MakeBadRequest(errors.New("This phone number is already added to an account. Please use a different phone number."))
	}

	pv := &database.PhoneVerification{
		Country:     *p.Country,
		Phone:       *p.Phone,
		OTP:         sms.GenerateOTP(),
		TimeExpires: time.Now().Add(time.Minute * 2),
		UserID:      uID,
	}

	if err := database.CreatePhoneVerification(ctx, pv); err != nil {
		return user.MakeInternalServerError(errors.New("An unknown error occurred. Please try again later."))
	}

	if err := sms.SendPhoneVerificationOTP(pv.Country, pv.Phone, pv.OTP); err != nil {
		return user.MakeInternalServerError(errors.New("Unable to send OTP sms. An unknown error occurred."))
	}

	return nil
}

func (s *UsersService) ResendOtp(ctx context.Context, p *user.ResendOtpPayload) error {
	uID := s.jwt.GetUserID(*p.Authorization)
	if uID == "" {
		return user.MakeUnauthorized(errors.New("unable to verify login status"))
	}

	pv, err := database.QueryPhoneVerificationByUserID(ctx, uID)
	if err != nil {
		return user.MakeInternalServerError(errors.New("An unknown error occurred. Please try again later."))
	}

	pv.OTP = sms.GenerateOTP()
	pv.TimeExpires = time.Now().Add(time.Minute * 2)

	if err := database.UpdatePhoneVerification(ctx, pv); err != nil {
		return user.MakeInternalServerError(errors.New("An unknown error occurred. Please try again later."))
	}

	if err := sms.SendPhoneVerificationOTP(pv.Country, pv.Phone, pv.OTP); err != nil {
		return user.MakeInternalServerError(errors.New("Unable to resend OTP. An unknown error occurred"))
	}

	return nil
}

func (s *UsersService) VerifyPhone(ctx context.Context, p *user.VerifyPhonePayload) error {
	uID := s.jwt.GetUserID(*p.Authorization)
	if uID == "" {
		return user.MakeUnauthorized(errors.New("unable to verify login status"))
	}

	pv, err := database.QueryPhoneVerificationByUserID(ctx, uID)
	if err != nil {
		return user.MakeInternalServerError(errors.New("An unknown error occurred. Please try again later."))
	}

	if pv.TimeExpires.Before(time.Now()) {
		return user.MakeBadRequest(errors.New("OTP has already expired. Please generate a new one."))
	} else if pv.OTP != *p.Otp {
		return user.MakeBadRequest(errors.New("Invalid OTP entered. Please try again."))
	} else {
		oid, _ := primitive.ObjectIDFromHex(uID)

		updatedUser := &models.User{
			ID: oid,
		}

		s.updateUserFields(updatedUser, &user.UserUpdateParams{
			Phone:            &pv.Phone,
			CountryPhoneCode: &pv.Country,
		})

		if err := database.UpdateUser(ctx, updatedUser); err != nil {
			return user.MakeInternalServerError(errors.New("Unable to update user phone. Please try again later."))
		}

		if err := database.DeletePhoneVerification(ctx, pv.ID.Hex()); err != nil {
			fmt.Println(err)
		}

		return nil
	}
}

func (s *UsersService) updateUserFields(u *models.User, p *user.UserUpdateParams) {
	if p.FirstName != nil {
		u.FirstName = *p.FirstName
	}
	if p.LastName != nil {
		u.LastName = *p.LastName
	}
	if p.Email != nil {
		u.Email = *p.Email
	}

	if p.CountryPhoneCode != nil {
		u.CountryPhoneCode = *p.CountryPhoneCode
	}

	if p.ChangingEmail != nil {
		u.ChangingEmail = *p.ChangingEmail
	}

	if p.VerifiedEmail != nil {
		u.VerifiedEmail = *p.VerifiedEmail
	}
	if p.IsAdmin != nil {
		u.IsAdmin = *p.IsAdmin
	}

	u.UpdatedAt = time.Now()
}

func createUser(ctx context.Context, u *models.User, recaptchaResponse *string, ipAddr string) (string, error) {
	if recaptchaResponse != nil {
		err := validateRecaptcha(ctx, *recaptchaResponse, ipAddr)
		if err != nil {
			return "", err
		}
	}

	u.CreatedAt = time.Now()

	uID, err := database.CreateUser(ctx, u)
	if err != nil {
		return "", err
	}

	if u.Email != "" && !u.VerifiedEmail {
		eID, err := generateEmailID(u.Email)
		if err != nil {
			return "", err
		}
		ev := &database.EmailVerification{
			ID:          eID,
			UserID:      uID,
			TimeExpires: time.Now().Add(emailValidateExpiration),
			Email:       u.Email,
		}
		err = database.CreateEmailVerification(ctx, ev)
		if err != nil {
			return "", err
		}

		redirectURl := os.Getenv("ClientURL") + "/influencer/verify-email/" + eID
		toName := u.FirstName + " " + u.LastName
		toMail := u.Email

		if err := email.SendVerificationEmail(toMail, toName, redirectURl); err != nil {
			return "", err
		}
	}

	return uID, nil
}

func validateRecaptcha(ctx context.Context, recaptchaResponse, ipAddr string) error {
	v := url.Values{}
	v.Set("secret", os.Getenv("RecaptchaSecret"))
	v.Set("response", recaptchaResponse)
	v.Set("remoteip", ipAddr)
	c := urlfetch.Client(ctx)
	recapRes, err := c.PostForm("https://www.google.com/recaptcha/api/siteverify", v)
	if err != nil {
		return err
	}
	defer recapRes.Body.Close()

	var recapResData struct {
		Success    bool
		ErrorCodes []string `json:"error-codes,omitempty"`
	}
	err = json.NewDecoder(recapRes.Body).Decode(&recapResData)
	if err != nil {
		return err
	}
	if !recapResData.Success {
		return ErrInvalidRecaptcha
	}
	return nil
}

func generateEmailID(emailAddr string) (string, error) {
	h := md5.New()
	_, err := io.WriteString(h, emailAddr)
	if err != nil {
		return "", err
	}
	_, err = io.WriteString(h, time.Now().String())
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func getNumLoginMethods(ctx context.Context, userID string) int64 {
	getAccountItems := []func(context.Context, string) (string, error){
		database.QueryGoogleAccountUser,
		database.QueryFacebookAccountUser,
		database.QueryPasswordLoginFromID,
	}
	var wg sync.WaitGroup
	var numLogins int64
	wg.Add(len(getAccountItems))
	for _, v := range getAccountItems {
		go func(command func(context.Context, string) (string, error)) {
			_, err := command(ctx, userID)
			if err == nil {
				atomic.AddInt64(&numLogins, 1)
			}
			wg.Done()
		}(v)
	}
	wg.Wait()
	return numLogins
}

type signer string

func (s signer) Sign(req *http.Request) error {
	req.Header.Set("Authorization", string(s))
	return nil
}

func Equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
