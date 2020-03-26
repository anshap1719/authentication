package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"github.com/anshap1719/authentication/utils/crypto"
	"github.com/anshap1719/authentication/utils/database"
	"github.com/gbrlsnchs/jwt/v3"
	"github.com/globalsign/mgo/bson"
	uuid "github.com/satori/go.uuid"
	"strconv"
	"strings"
	"time"
)

type JWTSecurity struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

type JWTPayload struct {
	jwt.Payload
	UserID         string `json:"sub,omitempty"`
	SessionID      string `json:"ses,omitempty"`
	IsAdmin        string `json:"adm,omitempty"`
}

type SessionPayload struct {
	jwt.Payload
	SessionID string `json:"prn,omitempty"`
}

var RSA *jwt.RSASHA

func NewJWTSecurity() (JWTSecurity, error) {
	var privFile map[string]interface{}
	var pubFile map[string]interface{}

	if res := database.GetCollection("Secrets").FindOne(context.TODO(), bson.M{"type": "JWTPrivateKey"}); res.Err() != nil {
		return JWTSecurity{}, res.Err()
	} else {
		res.Decode(&privFile)
	}

	if res := database.GetCollection("Secrets").FindOne(context.TODO(), bson.M{"type": "JWTPublicKey"}); res.Err() != nil {
		return JWTSecurity{}, res.Err()
	} else {
		res.Decode(&pubFile)
	}

	privStr := privFile["value"].(string)
	pubStr := pubFile["value"].(string)

	privKey, err := crypto.ParseRsaPrivateKeyFromPemStr(privStr)
	if err != nil {
		return JWTSecurity{}, nil
	}
	pubKey, err := crypto.ParseRsaPublicKeyFromPemStr(pubStr)
	if err != nil {
		return JWTSecurity{}, nil
	}

	RSA = jwt.NewRS512(jwt.RSAPrivateKey(privKey), jwt.RSAPublicKey(pubKey))

	return JWTSecurity{
		privateKey: privKey,
		publicKey:  pubKey,
	}, nil
}

func (j *JWTSecurity) IsAuthenticated(tokenString string) bool {
	token := strings.Replace(tokenString, "Bearer ", "", 1)
	pl, err := j.ValidateTokenAndGetClaims([]byte(token))

	if err != nil {
		return false
	}

	return pl.UserID != ""
}

func (j *JWTSecurity) IsAdmin(tokenString string) bool {
	token := strings.Replace(tokenString, "Bearer ", "", 1)
	pl, err := j.ValidateTokenAndGetClaims([]byte(token))
	if err != nil {
		return false
	}

	bo, _ := strconv.ParseBool(pl.IsAdmin)

	return bo
}

func (j *JWTSecurity) GetUserID(tokenString string) string {
	token := strings.Replace(tokenString, "Bearer ", "", 1)
	pl, err := j.ValidateTokenAndGetClaims([]byte(token))
	if err != nil {
		fmt.Println(err)
		return ""
	}

	return pl.UserID
}

func (j *JWTSecurity) GetSessionCode(tokenString string) string {
	token := strings.Replace(tokenString, "Bearer ", "", 1)
	pl, err := j.ValidateSessionAndGetClaims([]byte(token))
	if err != nil {
		return ""
	}

	return pl.SessionID
}

func (j *JWTSecurity) GetSessionFromAuth(tokenString string) string {
	token := strings.Replace(tokenString, "Bearer ", "", 1)
	pl, err := j.ValidateTokenAndGetClaims([]byte(token))
	if err != nil {
		return ""
	}

	return pl.SessionID
}

func (j *JWTSecurity) SignSessionToken(expTime time.Duration, sessionID string) (string, error) {
	tokenID := uuid.NewV4()

	now := time.Now()
	pl := SessionPayload{
		Payload: jwt.Payload{
			Issuer:         "issuer",
			Subject:        "session",
			ExpirationTime: jwt.NumericDate(now.Add(expTime)),
			NotBefore:      jwt.NumericDate(now),
			IssuedAt:       jwt.NumericDate(now),
			JWTID:          tokenID.String(),
		},
		SessionID: sessionID,
	}

	token, err := jwt.Sign(pl, RSA)
	return string(token), err
}

func (j *JWTSecurity) SignAuthToken(expTime time.Duration, sessionID, userID string, isAdmin bool) (string, error) {
	tokenID := uuid.NewV4()

	now := time.Now()
	pl := JWTPayload{
		Payload: jwt.Payload{
			Issuer:         "issuer",
			Subject:        "authentication",
			ExpirationTime: jwt.NumericDate(now.Add(expTime)),
			NotBefore:      jwt.NumericDate(now),
			IssuedAt:       jwt.NumericDate(now),
			JWTID:          tokenID.String(),
		},
		UserID:         userID,
		SessionID:      sessionID,
		IsAdmin:        strconv.FormatBool(isAdmin),
	}

	token, err := jwt.Sign(pl, RSA)
	return string(token), err
}

func (j *JWTSecurity) ValidateTokenAndGetClaims(token []byte) (*JWTPayload, error) {
	var (
		now = time.Now()

		iatValidator = jwt.IssuedAtValidator(now)
		expValidator = jwt.ExpirationTimeValidator(now)
		issValidator = jwt.IssuerValidator("issuer")

		pl              JWTPayload
		validatePayload = jwt.ValidatePayload(&pl.Payload, iatValidator, expValidator, issValidator)
	)

	_, err := jwt.Verify(token, RSA, &pl, validatePayload)
	if err != nil {
		return nil, err
	}

	return &pl, nil
}

func (j *JWTSecurity) ValidateSessionAndGetClaims(token []byte) (*SessionPayload, error) {
	var (
		now = time.Now()

		iatValidator = jwt.IssuedAtValidator(now)
		expValidator = jwt.ExpirationTimeValidator(now)
		issValidator = jwt.IssuerValidator("issuer")

		pl              SessionPayload
		validatePayload = jwt.ValidatePayload(&pl.Payload, iatValidator, expValidator, issValidator)
	)

	_, err := jwt.Verify(token, RSA, &pl, validatePayload)
	if err != nil {
		return nil, err
	}

	return &pl, nil
}
