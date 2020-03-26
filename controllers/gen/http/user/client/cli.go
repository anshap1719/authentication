// Code generated by goa v3.0.6, DO NOT EDIT.
//
// user HTTP client CLI support package
//
// Command:
// $ goa gen github.com/anshap1719/go-authentication/design

package client

import (
	"encoding/json"
	"fmt"

	user "github.com/anshap1719/go-authentication/controllers/gen/user"
)

// BuildGetAuthsPayload builds the payload for the user getAuths endpoint from
// CLI flags.
func BuildGetAuthsPayload(userGetAuthsUserID string, userGetAuthsAuthorization string, userGetAuthsXSession string, userGetAuthsAPIKey string) (*user.GetAuthsPayload, error) {
	var userID *string
	{
		if userGetAuthsUserID != "" {
			userID = &userGetAuthsUserID
		}
	}
	var authorization *string
	{
		if userGetAuthsAuthorization != "" {
			authorization = &userGetAuthsAuthorization
		}
	}
	var xSession *string
	{
		if userGetAuthsXSession != "" {
			xSession = &userGetAuthsXSession
		}
	}
	var aPIKey *string
	{
		if userGetAuthsAPIKey != "" {
			aPIKey = &userGetAuthsAPIKey
		}
	}
	payload := &user.GetAuthsPayload{
		UserID:        userID,
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}

// BuildDeactivatePayload builds the payload for the user deactivate endpoint
// from CLI flags.
func BuildDeactivatePayload(userDeactivateID string, userDeactivateAdmin string, userDeactivateAuthorization string, userDeactivateXSession string, userDeactivateAPIKey string) (*user.DeactivatePayload, error) {
	var id *string
	{
		if userDeactivateID != "" {
			id = &userDeactivateID
		}
	}
	var admin *string
	{
		if userDeactivateAdmin != "" {
			admin = &userDeactivateAdmin
		}
	}
	var authorization *string
	{
		if userDeactivateAuthorization != "" {
			authorization = &userDeactivateAuthorization
		}
	}
	var xSession *string
	{
		if userDeactivateXSession != "" {
			xSession = &userDeactivateXSession
		}
	}
	var aPIKey *string
	{
		if userDeactivateAPIKey != "" {
			aPIKey = &userDeactivateAPIKey
		}
	}
	payload := &user.DeactivatePayload{
		ID:            id,
		Admin:         admin,
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}

// BuildGetUserPayload builds the payload for the user getUser endpoint from
// CLI flags.
func BuildGetUserPayload(userGetUserAuthorization string, userGetUserXSession string, userGetUserAPIKey string) (*user.GetUserPayload, error) {
	var authorization *string
	{
		if userGetUserAuthorization != "" {
			authorization = &userGetUserAuthorization
		}
	}
	var xSession *string
	{
		if userGetUserXSession != "" {
			xSession = &userGetUserXSession
		}
	}
	var aPIKey *string
	{
		if userGetUserAPIKey != "" {
			aPIKey = &userGetUserAPIKey
		}
	}
	payload := &user.GetUserPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}

// BuildValidateEmailPayload builds the payload for the user validate-email
// endpoint from CLI flags.
func BuildValidateEmailPayload(userValidateEmailValidateID string, userValidateEmailAPIKey string) (*user.ValidateEmailPayload, error) {
	var validateID string
	{
		validateID = userValidateEmailValidateID
	}
	var aPIKey *string
	{
		if userValidateEmailAPIKey != "" {
			aPIKey = &userValidateEmailAPIKey
		}
	}
	payload := &user.ValidateEmailPayload{
		ValidateID: &validateID,
		APIKey:     aPIKey,
	}
	return payload, nil
}

// BuildUpdateUserPayload builds the payload for the user update-user endpoint
// from CLI flags.
func BuildUpdateUserPayload(userUpdateUserBody string, userUpdateUserAuthorization string, userUpdateUserXSession string, userUpdateUserAPIKey string) (*user.UserUpdateParams, error) {
	var err error
	var body UpdateUserRequestBody
	{
		err = json.Unmarshal([]byte(userUpdateUserBody), &body)
		if err != nil {
			return nil, fmt.Errorf("invalid JSON for body, example of valid JSON:\n%s", "'{\n      \"changingEmail\": \"Iure sequi magnam necessitatibus vel quis.\",\n      \"countryPhoneCode\": \"Qui numquam.\",\n      \"email\": \"Aperiam fuga a eum iste officiis blanditiis.\",\n      \"firstName\": \"Jeff\",\n      \"isAdmin\": false,\n      \"lastName\": \"Newmann\",\n      \"phone\": \"Distinctio aperiam.\",\n      \"verifiedEmail\": true\n   }'")
		}
	}
	var authorization *string
	{
		if userUpdateUserAuthorization != "" {
			authorization = &userUpdateUserAuthorization
		}
	}
	var xSession *string
	{
		if userUpdateUserXSession != "" {
			xSession = &userUpdateUserXSession
		}
	}
	var aPIKey *string
	{
		if userUpdateUserAPIKey != "" {
			aPIKey = &userUpdateUserAPIKey
		}
	}
	v := &user.UserUpdateParams{
		FirstName:        body.FirstName,
		LastName:         body.LastName,
		Email:            body.Email,
		Phone:            body.Phone,
		ChangingEmail:    body.ChangingEmail,
		VerifiedEmail:    body.VerifiedEmail,
		IsAdmin:          body.IsAdmin,
		CountryPhoneCode: body.CountryPhoneCode,
	}
	v.Authorization = authorization
	v.XSession = xSession
	v.APIKey = aPIKey
	return v, nil
}

// BuildResendVerifyEmailPayload builds the payload for the user
// resend-verify-email endpoint from CLI flags.
func BuildResendVerifyEmailPayload(userResendVerifyEmailAuthorization string, userResendVerifyEmailXSession string, userResendVerifyEmailAPIKey string) (*user.ResendVerifyEmailPayload, error) {
	var authorization *string
	{
		if userResendVerifyEmailAuthorization != "" {
			authorization = &userResendVerifyEmailAuthorization
		}
	}
	var xSession *string
	{
		if userResendVerifyEmailXSession != "" {
			xSession = &userResendVerifyEmailXSession
		}
	}
	var aPIKey *string
	{
		if userResendVerifyEmailAPIKey != "" {
			aPIKey = &userResendVerifyEmailAPIKey
		}
	}
	payload := &user.ResendVerifyEmailPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}

// BuildUpdatePhonePayload builds the payload for the user update-phone
// endpoint from CLI flags.
func BuildUpdatePhonePayload(userUpdatePhonePhone string, userUpdatePhoneCountry string, userUpdatePhoneAuthorization string, userUpdatePhoneXSession string, userUpdatePhoneAPIKey string) (*user.UpdatePhonePayload, error) {
	var phone *string
	{
		if userUpdatePhonePhone != "" {
			phone = &userUpdatePhonePhone
		}
	}
	var country *string
	{
		if userUpdatePhoneCountry != "" {
			country = &userUpdatePhoneCountry
		}
	}
	var authorization *string
	{
		if userUpdatePhoneAuthorization != "" {
			authorization = &userUpdatePhoneAuthorization
		}
	}
	var xSession *string
	{
		if userUpdatePhoneXSession != "" {
			xSession = &userUpdatePhoneXSession
		}
	}
	var aPIKey *string
	{
		if userUpdatePhoneAPIKey != "" {
			aPIKey = &userUpdatePhoneAPIKey
		}
	}
	payload := &user.UpdatePhonePayload{
		Phone:         phone,
		Country:       country,
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}

// BuildResendOtpPayload builds the payload for the user resend-otp endpoint
// from CLI flags.
func BuildResendOtpPayload(userResendOtpAuthorization string, userResendOtpXSession string, userResendOtpAPIKey string) (*user.ResendOtpPayload, error) {
	var authorization *string
	{
		if userResendOtpAuthorization != "" {
			authorization = &userResendOtpAuthorization
		}
	}
	var xSession *string
	{
		if userResendOtpXSession != "" {
			xSession = &userResendOtpXSession
		}
	}
	var aPIKey *string
	{
		if userResendOtpAPIKey != "" {
			aPIKey = &userResendOtpAPIKey
		}
	}
	payload := &user.ResendOtpPayload{
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}

// BuildVerifyPhonePayload builds the payload for the user verify-phone
// endpoint from CLI flags.
func BuildVerifyPhonePayload(userVerifyPhoneOtp string, userVerifyPhoneAuthorization string, userVerifyPhoneXSession string, userVerifyPhoneAPIKey string) (*user.VerifyPhonePayload, error) {
	var otp *string
	{
		if userVerifyPhoneOtp != "" {
			otp = &userVerifyPhoneOtp
		}
	}
	var authorization *string
	{
		if userVerifyPhoneAuthorization != "" {
			authorization = &userVerifyPhoneAuthorization
		}
	}
	var xSession *string
	{
		if userVerifyPhoneXSession != "" {
			xSession = &userVerifyPhoneXSession
		}
	}
	var aPIKey *string
	{
		if userVerifyPhoneAPIKey != "" {
			aPIKey = &userVerifyPhoneAPIKey
		}
	}
	payload := &user.VerifyPhonePayload{
		Otp:           otp,
		Authorization: authorization,
		XSession:      xSession,
		APIKey:        aPIKey,
	}
	return payload, nil
}
