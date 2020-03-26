package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type User struct {
	ID                primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	LastName          string        `json:"lastName,omitempty" bson:"lastName,omitempty"`
	UpdatedAt         time.Time     `json:"updatedAt,omitempty" bson:"updatedAt,omitempty"`
	Email             string        `json:"email,omitempty" bson:"email,omitempty"`
	IsActive          bool          `json:"isActive,omitempty" bson:"isActive,omitempty"`
	Password          string        `json:"password,omitempty" bson:"password,omitempty"`
	CreatedAt         time.Time     `json:"createdAt,omitempty" bson:"createdAt,omitempty"`
	FirstName         string        `json:"firstName,omitempty" bson:"firstName,omitempty"`
	ChangingEmail     string        `json:"changingEmail,omitempty" bson:"changingEmail,omitempty"`
	IsAdmin           bool          `json:"isAdmin,omitempty" bson:"isAdmin,omitempty"`
	VerifiedEmail     bool          `json:"verifiedEmail,omitempty" bson:"verifiedEmail,omitempty"`
	CountryPhoneCode  string        `json:"countryPhoneCode,omitempty" bson:"countryPhoneCode,omitempty"`
}

type PasswordLogin struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Email    string        `bson:"email,omitempty"`
	Password string        `bson:"password,omitempty"`
	Recovery string        `bson:"recovery,omitempty"`
	UserID   string        `bson:"userId,omitempty"`
}
