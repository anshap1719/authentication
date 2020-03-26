package database

import (
	"context"
	"errors"
	"github.com/anshap1719/authentication/models"
	"github.com/gofrs/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
)

var ErrFacebookAccountNotFound = errors.New("No FacebookAccount found in the database")
var ErrFacebookConnectionNotFound = errors.New("No FacebookConnection found in the database")
var ErrFacebookRegisterNotFound = errors.New("No FacebookRegister found in the database")

type FacebookRegister struct {
	FacebookID string `bson:"facebookId"`

	ID uuid.UUID `bson:"id"`

	TimeCreated time.Time `bson:"timeCreated"`
}

type FacebookConnection struct {
	MergeToken uuid.UUID `bson:"mergeToken"`

	Purpose int `bson:"purpose"`

	State uuid.UUID `bson:"state"`

	TimeCreated time.Time `bson:"timeCreated"`
}

type FacebookAccount struct {
	ID string `bson:"id"`

	UserID string `bson:"userId"`
}

func CreateFacebookAccount(ctx context.Context, newFacebookAccount *FacebookAccount) (err error) {
	if _, err := models.FacebookAccountCollection.InsertOne(ctx, newFacebookAccount); err != nil {
		return err
	}

	return nil
}

func GetFacebookAccount(ctx context.Context, ID string) (*FacebookAccount, error) {
	var fb FacebookAccount

	res := models.FacebookAccountCollection.FindOne(ctx, bson.M{"id": ID})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrFacebookAccountNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&fb); err != nil {
		return nil, err
	}

	return &fb, nil
}

func DeleteFacebookAccount(ctx context.Context, ID string) error {
	_, err := models.FacebookAccountCollection.DeleteOne(ctx, bson.M{"id": ID})
	return err
}

func QueryFacebookAccountUser(ctx context.Context, UserID string) (string, error) {
	var fb FacebookAccount

	res := models.FacebookAccountCollection.FindOne(ctx, bson.M{"userId": UserID})
	if res.Err() == mongo.ErrNoDocuments {
		return "", ErrFacebookAccountNotFound
	} else if res.Err() != nil {
		return "", res.Err()
	}

	if err := res.Decode(&fb); err != nil {
		return "", err
	}

	return fb.ID, nil
}

func CreateFacebookConnection(ctx context.Context, newFacebookConnection *FacebookConnection) (State uuid.UUID, err error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	newFacebookConnection.State = uid

	if _, err := models.FacebookConnectionCollection.InsertOne(ctx, newFacebookConnection); err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}

func GetFacebookConnection(ctx context.Context, State uuid.UUID) (*FacebookConnection, error) {
	var fb FacebookConnection

	res := models.FacebookConnectionCollection.FindOne(ctx, bson.M{"state": State})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrFacebookConnectionNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&fb); err != nil {
		return nil, err
	}

	return &fb, nil
}

func DeleteFacebookConnection(ctx context.Context, State uuid.UUID) error {
	_, err := models.FacebookConnectionCollection.DeleteOne(ctx, bson.M{"state": State})
	return err
}

func CreateFacebookRegister(ctx context.Context, newFacebookRegister *FacebookRegister) (ID uuid.UUID, err error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	newFacebookRegister.ID = uid

	if _, err := models.FacebookRegisterCollection.InsertOne(ctx, newFacebookRegister); err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}

func GetFacebookRegister(ctx context.Context, ID uuid.UUID) (*FacebookRegister, error) {
	var fb FacebookRegister

	res := models.FacebookRegisterCollection.FindOne(ctx, bson.M{"id": ID})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrFacebookRegisterNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&fb); err != nil {
		return nil, err
	}

	return &fb, nil
}

func DeleteFacebookRegister(ctx context.Context, ID uuid.UUID) error {
	_, err := models.FacebookRegisterCollection.DeleteOne(ctx, bson.M{"id": ID})
	return err
}
