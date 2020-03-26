package database

import (
	"context"
	"github.com/anshap1719/authentication/models"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
)

var ErrMergeTokenNotFound = errors.New("No MergeToken found in the database")
var ErrPasswordLoginNotFound = errors.New("No PasswordLogin found in the database")
var ErrResetPasswordNotFound = errors.New("No ResetPassword found in the database")

type ResetPassword struct {
	ID uuid.UUID `bson:"id"`

	TimeExpires time.Time `bson:"timeExpires"`

	UserID string `bson:"userId"`
}

type PasswordLogin struct {
	ID primitive.ObjectID `bson:"_id,omitempty"`

	Email string `bson:"email"`

	Password string `bson:"password"`

	Recovery string `bson:"recovery"`

	UserID string `bson:"userId"`
}

func GetPasswordLogin(ctx context.Context, Email string) (*PasswordLogin, error) {
	var t PasswordLogin

	res := models.PasswordLoginCollection.FindOne(ctx, bson.M{"email": Email})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrPasswordLoginNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&t); err != nil {
		return nil, err
	}

	return &t, nil
}

func UpdatePasswordLogin(ctx context.Context, updatedPasswordLogin *PasswordLogin) error {
	if _, err := models.PasswordLoginCollection.UpdateOne(ctx, bson.M{"email": updatedPasswordLogin.Email}, bson.M{
		"$set": updatedPasswordLogin,
	}); err == mongo.ErrNoDocuments {
		return ErrPasswordLoginNotFound
	} else if err != nil {
		return err
	}

	return nil
}

func DeletePasswordLogin(ctx context.Context, Email string) error {
	if _, err := models.PasswordLoginCollection.DeleteOne(ctx, bson.M{"email": Email}); err == mongo.ErrNoDocuments {
		return ErrPasswordLoginNotFound
	} else if err != nil {
		return err
	}

	return nil
}

func QueryPasswordLoginFromID(ctx context.Context, UserID string) (string, error) {
	var pl PasswordLogin

	res := models.UsersCollection.FindOne(ctx, bson.M{"userId": UserID})
	if res.Err() == mongo.ErrNoDocuments {
		return "", ErrPasswordLoginNotFound
	} else if res.Err() != nil {
		return "", res.Err()
	}

	if err := res.Decode(&pl); err != nil {
		return "", err
	}

	return pl.ID.Hex(), nil
}

func CreateResetPassword(ctx context.Context, newResetPassword *ResetPassword) error {
	_, err := models.ResetPasswordCollection.InsertOne(ctx, newResetPassword)
	return err
}

func GetResetPassword(ctx context.Context, UserID string) (*ResetPassword, error) {
	var rp ResetPassword

	res := models.ResetPasswordCollection.FindOne(ctx, bson.M{"userId": UserID})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrResetPasswordNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&rp); err != nil {
		return nil, err
	}

	return &rp, nil
}

func DeleteResetPassword(ctx context.Context, UserID string) error {
	_, err := models.ResetPasswordCollection.DeleteOne(ctx, bson.M{"userId": UserID})
	return err
}
