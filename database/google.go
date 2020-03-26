package database

import (
	"context"
	"errors"
	"github.com/anshap1719/authentication/models"
	"github.com/gofrs/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

var ErrGoogleConnectionNotFound = errors.New("No GoogleConnection found in the database")
var ErrGoogleAccountNotFound = errors.New("No GoogleAccount found in the database")
var ErrGoogleRegisterNotFound = errors.New("No GoogleRegister found in the database")

type GoogleRegister struct {
	GoogleEmail string `bson:"googleEmail"`

	ID uuid.UUID `bson:"id"`

	TimeCreated time.Time `bson:"timeCreated"`
}

type GoogleAccount struct {
	ID primitive.ObjectID `bson:"_id,omitempty"`

	GoogleEmail string `bson:"googleEmail"`

	UserID string `bson:"userId"`
}

type GoogleConnection struct {
	ID primitive.ObjectID `bson:"_id,omitempty"`

	MergeToken uuid.UUID `bson:"mergeToken"`

	Purpose int `bson:"purpose"`

	State uuid.UUID `bson:"state"`

	TimeCreated time.Time `bson:"timeCreated"`
}

func CreateGoogleConnection(ctx context.Context, newGoogleConnection *GoogleConnection) (State uuid.UUID, err error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	newGoogleConnection.State = uid

	if _, err := models.GoogleConnectionCollection.InsertOne(ctx, newGoogleConnection); err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}

func GetGoogleConnection(ctx context.Context, State uuid.UUID) (*GoogleConnection, error) {
	var gc GoogleConnection

	res := models.GoogleConnectionCollection.FindOne(ctx, bson.M{"state": State})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrGoogleConnectionNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&gc); err != nil {
		return nil, err
	}

	return &gc, nil
}

func DeleteGoogleConnection(ctx context.Context, State uuid.UUID) error {
	_, err := models.GoogleConnectionCollection.DeleteOne(ctx, bson.M{"state": State})
	return err
}

func CreateGoogleAccount(ctx context.Context, newGoogleAccount *GoogleAccount) error {
	_, err := models.GoogleAccountCollection.InsertOne(ctx, newGoogleAccount)
	return err
}

func GetGoogleAccount(ctx context.Context, GoogleEmail string) (*GoogleAccount, error) {
	var ga GoogleAccount

	res := models.GoogleAccountCollection.FindOne(ctx, bson.M{"googleEmail": GoogleEmail})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrGoogleAccountNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&ga); err != nil {
		return nil, err
	}

	return &ga, nil
}

func DeleteGoogleAccount(ctx context.Context, GoogleEmail string) error {
	_, err := models.GoogleAccountCollection.DeleteOne(ctx, bson.M{"googleEmail": GoogleEmail})
	return err
}

func QueryGoogleAccountUser(ctx context.Context, UserID string) (string, error) {
	res := models.GoogleAccountCollection.FindOne(ctx, bson.M{"userId": UserID}, options.FindOne().SetProjection(bson.M{"googleEmail": 1}))
	if res.Err() == mongo.ErrNoDocuments {
		return "", ErrGoogleAccountNotFound
	} else if res.Err() != nil {
		return "", res.Err()
	}

	var ga GoogleAccount
	if err := res.Decode(&ga); err != nil {
		return "", err
	}

	return ga.GoogleEmail, nil
}

func CreateGoogleRegister(ctx context.Context, newGoogleRegister *GoogleRegister) (ID uuid.UUID, err error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	newGoogleRegister.ID = uid

	if _, err := models.GoogleRegisterCollection.InsertOne(ctx, newGoogleRegister); err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}

func GetGoogleRegister(ctx context.Context, ID uuid.UUID) (*GoogleRegister, error) {
	var gr GoogleRegister

	res := models.GoogleRegisterCollection.FindOne(ctx, bson.M{"id": ID})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrGoogleRegisterNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&gr); err != nil {
		return nil, err
	}

	return &gr, nil
}

func DeleteGoogleRegister(ctx context.Context, ID uuid.UUID) error {
	_, err := models.GoogleRegisterCollection.DeleteOne(ctx, bson.M{"id": ID})
	return err
}
