package controllers

import (
	"context"
	"errors"
	"fmt"
	"github.com/alioygur/is"
	passwordauth "github.com/anshap1719/authentication/controllers/gen/password_auth"
	"github.com/anshap1719/authentication/database"
	"github.com/anshap1719/authentication/models"
	"github.com/anshap1719/authentication/utils/auth"
	. "github.com/anshap1719/authentication/utils/ctx"
	"github.com/anshap1719/authentication/utils/email"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/gofrs/uuid"
	"github.com/simukti/emailcheck"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"
)

// PasswordAuthService implements the password-auth resource.
type PasswordAuthService struct {
	log     *log.Logger
	jwt     *auth.JWTSecurity
	session *SessionService
}

// NewPasswordAuthService creates a password-auth controller.
func NewPasswordAuthService(log *log.Logger, jwt *auth.JWTSecurity, session *SessionService) passwordauth.Service {
	return &PasswordAuthService{
		log:     log,
		jwt:     jwt,
		session: session,
	}
}

func (s *PasswordAuthService) CheckEmailAvailable(ctx context.Context, p *passwordauth.CheckEmailAvailablePayload) (res bool, err error) {
	if exists := CheckEmailExists(*p.Email); !exists {
		return true, nil
	} else {
		return false, nil
	}
}

func (s *PasswordAuthService) CheckPhoneAvailable(ctx context.Context, p *passwordauth.CheckPhoneAvailablePayload) (res bool, err error) {
	if exists := CheckPhoneExists(*p.Phone); !exists {
		return true, nil
	} else {
		return false, nil
	}
}

// Register a new user with an email and password
func (s *PasswordAuthService) Register(ctx context.Context, p *passwordauth.RegisterParams) (res *passwordauth.UserMedia, err error) {
	if !is.Email(strings.ToLower(p.Email)) {
		return nil, passwordauth.MakeBadRequest(errors.New("invalid email provided"))
	}
	if emailcheck.IsDisposableEmail(strings.ToLower(p.Email)) {
		return nil, passwordauth.MakeForbidden(errors.New("disposable email not allowed"))
	}

	if emailExist := CheckEmailExists(p.Email); emailExist {
		return nil, passwordauth.MakeForbidden(errors.New("Email already exists"))
	}

	_, _, err2 := net.SplitHostPort("")
	if err2 != nil {
		_ = ""
	}

	payload := p

	cryptPass, err := bcrypt.GenerateFromPassword([]byte(p.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, passwordauth.MakeInternalServerError(err)
	}

	newU := models.User{
		Email:             payload.Email,
		FirstName:         payload.FirstName,
		LastName:          payload.LastName,
		Password:          string(cryptPass),
		VerifiedEmail:     false,
		IsAdmin:           false,
	}

	remoteAddrInt := ctx.Value(RequestXForwardedForKey)
	var remoteAddr string

	if remoteAddrInt == nil || (reflect.ValueOf(remoteAddrInt).Kind() != reflect.String) {
		remoteAddr = ""
	} else {
		remoteAddr = remoteAddrInt.(string)
	}

	uID, err := createUser(ctx, &newU, &p.GRecaptchaResponse, remoteAddr)
	if err != nil {
		return nil, passwordauth.MakeInternalServerError(err)
	}

	recoveryID, _ := uuid.NewV4()

	passl := models.PasswordLogin{
		Email:    strings.ToLower(p.Email),
		UserID:   uID,
		Password: string(cryptPass),
		Recovery: recoveryID.String(),
	}

	if _, err := models.PasswordLoginCollection.InsertOne(context.Background(), &passl); err != nil {
		fmt.Printf("%v", err)
		return nil, passwordauth.MakeInternalServerError(err)
	}

	sesToken, authToken, err := s.session.loginUser(ctx, newU, remoteAddr, ctx.Value(RequestUserAgentKey).(string))
	if err != nil {
		return nil, passwordauth.MakeInternalServerError(err)
	}

	user := database.UserToUser(&newU)

	token := "Bearer " + authToken

	return &passwordauth.UserMedia{
		ID:             uID,
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		Email:          user.Email,
		ChangingEmail:  user.ChangingEmail,
		VerifiedEmail:  user.VerifiedEmail,
		IsAdmin:        user.IsAdmin,
		Authorization:  token,
		XSession:       sesToken,
	}, nil
}

// Login a user using an email and password
func (s *PasswordAuthService) Login(ctx context.Context, p *passwordauth.LoginParams) (res *passwordauth.UserMedia, err error) {
	passl, err := database.GetPasswordLogin(ctx, strings.ToLower(p.Email))
	if err == database.ErrPasswordLoginNotFound {
		fmt.Println(database.ErrPasswordLoginNotFound)
		return nil, passwordauth.MakeUnauthorized(errors.New("Email or password does not match"))
	} else if err != nil {
		fmt.Println("1", err)
		return nil, passwordauth.MakeInternalServerError(err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(passl.Password), []byte(p.Password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		fmt.Println(bcrypt.ErrMismatchedHashAndPassword)
		return nil, passwordauth.MakeUnauthorized(errors.New("Email or password does not match"))
	} else if err != nil {
		fmt.Println("2", err)
		return nil, passwordauth.MakeInternalServerError(err)
	}

	fmt.Println(passl.UserID)

	u, err := database.GetUser(ctx, passl.UserID)
	if err != nil {
		fmt.Println("3", err)
		return nil, passwordauth.MakeInternalServerError(err)
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
		fmt.Println("4", err)
		return nil, passwordauth.MakeInternalServerError(err)
	}

	user := database.UserToUser(u)

	token := "Bearer " + authToken

	return &passwordauth.UserMedia{
		ID:             user.ID,
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		Email:          user.Email,
		Phone:          user.Phone,
		ChangingEmail:  user.ChangingEmail,
		VerifiedEmail:  user.VerifiedEmail,
		IsAdmin:        user.IsAdmin,
		Authorization:  token,
		XSession:       sesToken,
	}, nil
}

// Removes using a password as a login method
func (s *PasswordAuthService) Remove(ctx context.Context, p *passwordauth.RemovePayload) (err error) {
	uID := s.jwt.GetUserID(*p.Authorization)

	if getNumLoginMethods(ctx, uID) <= 1 {
		return passwordauth.MakeForbidden(errors.New("Cannot remove password if it is the only way to login"))
	}

	pID, err := database.QueryPasswordLoginFromID(ctx, uID)
	if err == database.ErrPasswordLoginNotFound {
		return passwordauth.MakeNotFound(errors.New("User account does not have a password"))
	} else if err != nil {
		return passwordauth.MakeInternalServerError(err)
	}

	err = database.DeletePasswordLogin(ctx, pID)
	if err != nil {
		return passwordauth.MakeInternalServerError(err)
	}

	return nil
}

// Changes the user's current password to a new one, also adds a password to
// the account if there is none
func (s *PasswordAuthService) ChangePassword(ctx context.Context, p *passwordauth.ChangePasswordParams) (err error) {
	uID := s.jwt.GetUserID(p.Authorization)

	u, err := database.GetUser(ctx, uID)
	if err != nil {
		return passwordauth.MakeInternalServerError(err)
	}

	passl, err := database.GetPasswordLogin(ctx, strings.ToLower(u.Email))
	if err == database.ErrPasswordLoginNotFound && p.OldPassword == nil {
		cryptPass, err := bcrypt.GenerateFromPassword([]byte(p.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			return passwordauth.MakeInternalServerError(err)
		}

		newP := database.PasswordLogin{
			Email:    u.Email,
			UserID:   u.ID.Hex(),
			Password: string(cryptPass),
		}

		if _, err := models.PasswordLoginCollection.InsertOne(ctx, &newP); err != nil {
			fmt.Printf("%v", err)
			return passwordauth.MakeInternalServerError(err)
		}

		sesID := s.jwt.GetSessionFromAuth(p.Authorization)
		err = logoutAllSessionsBut(ctx, uID, sesID)
		if err != nil {
			s.log.Println("Unable to logout of other sessions when changing password")
		}

		return nil
	} else if err != nil {
		return passwordauth.MakeInternalServerError(err)
	} else if p.OldPassword == nil {
		return passwordauth.MakeBadRequest(errors.New("Old password is invalid. Please try again."))
	}

	err = bcrypt.CompareHashAndPassword([]byte(passl.Password), []byte(*p.OldPassword))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		fmt.Println(bcrypt.ErrMismatchedHashAndPassword)
		return passwordauth.MakeBadRequest(errors.New("Old password is invalid. Please try again."))
	} else if err != nil {
		return passwordauth.MakeInternalServerError(err)
	}

	cryptPass, err := bcrypt.GenerateFromPassword([]byte(p.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return passwordauth.MakeInternalServerError(err)
	}

	newP := database.PasswordLogin{
		Email:    u.Email,
		UserID:   u.ID.Hex(),
		Password: string(cryptPass),
	}
	err = database.UpdatePasswordLogin(ctx, &newP)
	if err != nil {
		return passwordauth.MakeInternalServerError(err)
	}

	sesID := s.jwt.GetSessionFromAuth(p.Authorization)
	err = logoutAllSessionsBut(ctx, uID, sesID)
	if err != nil {
		s.log.Println("Unable to logout of other sessions when changing password")
	}

	return nil
}

// Send an email to user to get a password reset, responds with no content even
// if the email is not on any user account
func (s *PasswordAuthService) Reset(ctx context.Context, p *passwordauth.ResetPayload) (err error) {
	u, err := database.QueryUserEmail(ctx, strings.ToLower(*p.Email))
	if err == database.ErrUserNotFound {
		return nil
	} else if err != nil {
		return passwordauth.MakeNotFound(err)
	}

	var id uuid.UUID
	rp, err := database.GetResetPassword(ctx, u.ID.Hex())
	if err == nil {
		id = rp.ID
	} else if err == database.ErrResetPasswordNotFound {
		id, err = uuid.NewV4()
		if err != nil {
			return err
		}
	} else {
		return passwordauth.MakeInternalServerError(err)
	}

	err = database.CreateResetPassword(ctx, &database.ResetPassword{
		UserID:      u.ID.Hex(),
		ID:          id,
		TimeExpires: time.Now().Add(120 * time.Minute),
	})
	if err != nil {
		return passwordauth.MakeInternalServerError(err)
	}

	target := fmt.Sprintf("%s/influencer/reset-password?code=%s&uid=%s", os.Getenv("ClientURL"), url.QueryEscape(id.String()), url.QueryEscape(u.ID.Hex()))

	if err := email.SendResetPassword(u.Email, u.FirstName+" "+u.LastName, target); err != nil {
		return passwordauth.MakeInternalServerError(err)
	}

	return nil
}

// Confirms that a reset has been completed and changes the password to the new
// one passed in
func (s *PasswordAuthService) ConfirmReset(ctx context.Context, p *passwordauth.ResetPasswordParams) (err error) {
	rp, err := database.GetResetPassword(ctx, p.UserID)
	if err == database.ErrResetPasswordNotFound {
		return passwordauth.MakeForbidden(errors.New("Invalid reset code"))
	} else if err != nil {
		return passwordauth.MakeInternalServerError(err)
	}

	fmt.Println(rp)

	if time.Now().After(rp.TimeExpires) {
		database.DeleteResetPassword(ctx, rp.UserID)
		return passwordauth.MakeForbidden(errors.New("Invalid reset code"))
	}

	fmt.Println(rp.ID.String(), p.ResetCode)

	if rp.ID.String() != p.ResetCode {
		return passwordauth.MakeForbidden(errors.New("Invalid reset code"))
	}

	u, err := database.GetUser(ctx, rp.UserID)
	if err != nil {
		return passwordauth.MakeInternalServerError(err)
	}

	cryptPass, err := bcrypt.GenerateFromPassword([]byte(p.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return passwordauth.MakeInternalServerError(err)
	}

	err = database.UpdatePasswordLogin(ctx, &database.PasswordLogin{
		Email:    u.Email,
		UserID:   u.ID.Hex(),
		Password: string(cryptPass),
	})
	if err != nil {
		return passwordauth.MakeInternalServerError(err)
	}

	err = logoutAllSessionsBut(ctx, rp.UserID, "")
	if err != nil {
		s.log.Println("Unable to logout of all sessions when resetting password")
	}

	return nil
}

func CheckEmailExists(email string) bool {
	if count, err := models.UsersCollection.CountDocuments(context.Background(), bson.M{"email": email}); err == mgo.ErrNotFound {
		return false
	} else if err != nil {
		return true
	} else if count > 0 {
		return true
	}

	return false
}

func CheckPhoneExists(phone string) bool {
	if count, err := models.UsersCollection.CountDocuments(context.Background(), bson.M{"phone": phone}); err == mgo.ErrNotFound {
		return false
	} else if err != nil {
		return true
	} else if count > 0 {
		return true
	}

	return false
}
