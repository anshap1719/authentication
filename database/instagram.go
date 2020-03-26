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

var ErrInstagramAccountNotFound = errors.New("No InstagramAccount found in the database")
var ErrInstagramConnectionNotFound = errors.New("No InstagramConnection found in the database")
var ErrInstagramRegisterNotFound = errors.New("No InstagramRegister found in the database")

type InstagramRegister struct {
	InstagramID string `bson:"instagramId"`

	ID uuid.UUID `bson:"id"`

	TimeCreated time.Time `bson:"timeCreated"`
}

type InstagramConnection struct {
	MergeToken uuid.UUID `bson:"mergeToken"`

	Purpose int `bson:"purpose"`

	State uuid.UUID `bson:"state"`

	TimeCreated time.Time `bson:"timeCreated"`
}

type InstagramAccount struct {
	ID string `bson:"id"`

	UserID string `bson:"userId"`

	InstagramUsername string `bson:"instagramUsername"`

	RawData map[string]interface{} `bson:"rawData"`
}

func CreateInstagramAccount(ctx context.Context, newInstagramAccount *InstagramAccount) (err error) {
	if _, err := models.InstagramAccountCollection.InsertOne(ctx, newInstagramAccount); err != nil {
		return err
	}

	return nil
}

func GetInstagramAccount(ctx context.Context, ID string) (*InstagramAccount, error) {
	var fb InstagramAccount

	res := models.InstagramAccountCollection.FindOne(ctx, bson.M{"id": ID})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrInstagramAccountNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&fb); err != nil {
		return nil, err
	}

	return &fb, nil
}

func DeleteInstagramAccount(ctx context.Context, ID string) error {
	_, err := models.InstagramAccountCollection.DeleteOne(ctx, bson.M{"id": ID})
	return err
}

func QueryInstagramAccountUser(ctx context.Context, UserID string) (string, error) {
	var fb InstagramAccount

	res := models.InstagramAccountCollection.FindOne(ctx, bson.M{"userId": UserID})
	if res.Err() == mongo.ErrNoDocuments {
		return "", ErrInstagramAccountNotFound
	} else if res.Err() != nil {
		return "", res.Err()
	}

	if err := res.Decode(&fb); err != nil {
		return "", err
	}

	return fb.ID, nil
}

func CreateInstagramConnection(ctx context.Context, newInstagramConnection *InstagramConnection) (State uuid.UUID, err error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	newInstagramConnection.State = uid

	if _, err := models.InstagramConnectionCollection.InsertOne(ctx, newInstagramConnection); err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}

func GetInstagramConnection(ctx context.Context, State uuid.UUID) (*InstagramConnection, error) {
	var fb InstagramConnection

	res := models.InstagramConnectionCollection.FindOne(ctx, bson.M{"state": State})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrInstagramConnectionNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&fb); err != nil {
		return nil, err
	}

	return &fb, nil
}

func DeleteInstagramConnection(ctx context.Context, State uuid.UUID) error {
	_, err := models.InstagramConnectionCollection.DeleteOne(ctx, bson.M{"state": State})
	return err
}

func CreateInstagramRegister(ctx context.Context, newInstagramRegister *InstagramRegister) (ID uuid.UUID, err error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	newInstagramRegister.ID = uid

	if _, err := models.InstagramRegisterCollection.InsertOne(ctx, newInstagramRegister); err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}

func DeleteInstagramRegister(ctx context.Context, ID uuid.UUID) error {
	_, err := models.InstagramRegisterCollection.DeleteOne(ctx, bson.M{"id": ID})
	return err
}
