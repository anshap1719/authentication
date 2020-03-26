package database

import (
	"context"
	"errors"
	"github.com/anshap1719/authentication/models"
	"github.com/gofrs/uuid"
	"github.com/mrjones/oauth"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
)

var ErrTwitterAccountNotFound = errors.New("No TwitterAccount found in the database")
var ErrTwitterConnectionNotFound = errors.New("No TwitterConnection found in the database")
var ErrTwitterRegisterNotFound = errors.New("No TwitterRegister found in the database")

type TwitterRegister struct {
	TwitterID string `bson:"facebookId"`

	ID uuid.UUID `bson:"id"`

	TimeCreated time.Time `bson:"timeCreated"`
}

type TwitterConnection struct {
	MergeToken uuid.UUID `bson:"mergeToken"`

	Purpose int `bson:"purpose"`

	State uuid.UUID `bson:"state"`

	TimeCreated time.Time `bson:"timeCreated"`
}

type TwitterAccount struct {
	ID string `bson:"id"`

	UserID string `bson:"userId"`
}

func CreateTwitterAccount(ctx context.Context, newTwitterAccount *TwitterAccount) (err error) {
	if _, err := models.TwitterAccountCollection.InsertOne(ctx, newTwitterAccount); err != nil {
		return err
	}

	return nil
}

func GetTwitterAccount(ctx context.Context, ID string) (*TwitterAccount, error) {
	var fb TwitterAccount

	res := models.TwitterAccountCollection.FindOne(ctx, bson.M{"id": ID})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrTwitterAccountNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&fb); err != nil {
		return nil, err
	}

	return &fb, nil
}

func DeleteTwitterAccount(ctx context.Context, ID string) error {
	_, err := models.TwitterAccountCollection.DeleteOne(ctx, bson.M{"id": ID})
	return err
}

func QueryTwitterAccountUser(ctx context.Context, UserID string) (string, error) {
	var fb TwitterAccount

	res := models.TwitterAccountCollection.FindOne(ctx, bson.M{"userId": UserID})
	if res.Err() == mongo.ErrNoDocuments {
		return "", ErrTwitterAccountNotFound
	} else if res.Err() != nil {
		return "", res.Err()
	}

	if err := res.Decode(&fb); err != nil {
		return "", err
	}

	return fb.ID, nil
}

func CreateTwitterConnection(ctx context.Context, newTwitterConnection *TwitterConnection) (State uuid.UUID, err error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	newTwitterConnection.State = uid

	if _, err := models.TwitterConnectionCollection.InsertOne(ctx, newTwitterConnection); err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}

func GetTwitterConnection(ctx context.Context, State uuid.UUID) (*TwitterConnection, error) {
	var fb TwitterConnection

	res := models.TwitterConnectionCollection.FindOne(ctx, bson.M{"state": State})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrTwitterConnectionNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&fb); err != nil {
		return nil, err
	}

	return &fb, nil
}

func DeleteTwitterConnection(ctx context.Context, State uuid.UUID) error {
	_, err := models.TwitterConnectionCollection.DeleteOne(ctx, bson.M{"state": State})
	return err
}

func CreateTwitterRegister(ctx context.Context, newTwitterRegister *TwitterRegister) (ID uuid.UUID, err error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	newTwitterRegister.ID = uid

	if _, err := models.TwitterRegisterCollection.InsertOne(ctx, newTwitterRegister); err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}

func GetTwitterRegister(ctx context.Context, ID uuid.UUID) (*TwitterRegister, error) {
	var fb TwitterRegister

	res := models.TwitterRegisterCollection.FindOne(ctx, bson.M{"id": ID})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrTwitterRegisterNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&fb); err != nil {
		return nil, err
	}

	return &fb, nil
}

func DeleteTwitterRegister(ctx context.Context, ID uuid.UUID) error {
	_, err := models.TwitterRegisterCollection.DeleteOne(ctx, bson.M{"id": ID})
	return err
}

func GetTwitterToken(key string) (*oauth.RequestToken, error) {
	var token struct {
		Key   string
		Token oauth.RequestToken
	}

	ctx := context.TODO()

	res := models.TwitterTokenCollection.FindOne(ctx, bson.M{"key": key})
	if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&token); err != nil {
		return nil, err
	}

	return &token.Token, nil
}

func CreateTwitterToken(key string, token oauth.RequestToken) error {
	var t = struct {
		Key   string
		Token oauth.RequestToken
	}{
		Key:   key,
		Token: token,
	}

	ctx := context.TODO()

	_, err := models.TwitterTokenCollection.InsertOne(ctx, &t)
	return err
}

func DeleteTwitterToken(key string) error {
	ctx := context.TODO()
	_, err := models.TwitterTokenCollection.DeleteOne(ctx, bson.M{"key": key})
	return err
}
