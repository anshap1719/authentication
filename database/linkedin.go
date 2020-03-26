package database

import (
	"context"
	"errors"
	"github.com/anshap1719/authentication/models"
	"github.com/gofrs/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

var ErrLinkedinAccountNotFound = errors.New("No LinkedinAccount found in the database")
var ErrLinkedinConnectionNotFound = errors.New("No LinkedinConnection found in the database")
var ErrLinkedinRegisterNotFound = errors.New("No LinkedinRegister found in the database")

type LinkedinRegister struct {
	ID uuid.UUID `bson:"id"`

	LinkedinEmail string `bson:"linkedinEmail"`

	TimeCreated time.Time `bson:"timeCreated"`
}

type LinkedinConnection struct {
	MergeToken uuid.UUID `bson:"mergeToken"`

	Purpose int `bson:"purpose"`

	State uuid.UUID `bson:"state"`

	TimeCreated time.Time `bson:"timeCreated"`
}

type LinkedinAccount struct {
	LinkedinEmail string `bson:"linkedinEmail"`

	UserID string `bson:"userId"`
}

func CreateLinkedinAccount(ctx context.Context, newLinkedinAccount *LinkedinAccount) error {
	_, err := models.LinkedinAccountCollection.InsertOne(ctx, newLinkedinAccount)
	return err
}

func GetLinkedinAccount(ctx context.Context, LinkedinEmail string) (*LinkedinAccount, error) {
	var la LinkedinAccount

	res := models.LinkedinAccountCollection.FindOne(ctx, bson.M{"linkedinEmail": LinkedinEmail})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrLinkedinAccountNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&la); err != nil {
		return nil, err
	}

	return &la, nil
}

func DeleteLinkedinAccount(ctx context.Context, LinkedinEmail string) error {
	_, err := models.LinkedinAccountCollection.DeleteOne(ctx, bson.M{"linkedinEmail": LinkedinEmail})
	return err
}

func QueryLinkedinAccountUser(ctx context.Context, UserID string) (string, error) {
	var ID []string

	curr, err := models.LinkedinAccountCollection.Find(ctx, bson.M{"userId": UserID}, options.Find().SetProjection(bson.M{"linkedinEmail": 1}))
	if err == mongo.ErrNoDocuments {
		return "", ErrLinkedinAccountNotFound
	} else if err != nil {
		return "", err
	}

	for curr.Next(ctx) {
		if curr.Err() != nil {
			continue
		}
		var la LinkedinAccount
		if err := curr.Decode(&la); err != nil {
			continue
		}

		ID = append(ID, la.LinkedinEmail)
	}

	if len(ID) == 0 {
		return "", ErrLinkedinAccountNotFound
	}

	return ID[0], nil
}

func CreateLinkedinConnection(ctx context.Context, newLinkedinConnection *LinkedinConnection) (State uuid.UUID, err error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	newLinkedinConnection.State = uid
	_, err = models.LinkedinConnectionCollection.InsertOne(ctx, newLinkedinConnection)

	return uid, err
}

func GetLinkedinConnection(ctx context.Context, State uuid.UUID) (*LinkedinConnection, error) {
	var lc LinkedinConnection

	res := models.LinkedinConnectionCollection.FindOne(ctx, bson.M{"state": State})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrLinkedinConnectionNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&lc); err != nil {
		return nil, err
	}

	return &lc, nil
}

func DeleteLinkedinConnection(ctx context.Context, State uuid.UUID) error {
	_, err := models.LinkedinConnectionCollection.DeleteOne(ctx, bson.M{"state": State})
	return err
}

func CreateLinkedinRegister(ctx context.Context, newLinkedinRegister *LinkedinRegister) (ID uuid.UUID, err error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	newLinkedinRegister.ID = uid
	_, err = models.LinkedinRegisterCollection.InsertOne(ctx, newLinkedinRegister)

	return uid, err
}

func GetLinkedinRegister(ctx context.Context, ID uuid.UUID) (*LinkedinRegister, error) {
	var lr LinkedinRegister

	res := models.LinkedinRegisterCollection.FindOne(ctx, bson.M{"id": ID})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrLinkedinRegisterNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&lr); err != nil {
		return nil, err
	}

	return &lr, nil
}

func DeleteLinkedinRegister(ctx context.Context, ID uuid.UUID) error {
	_, err := models.LinkedinRegisterCollection.DeleteOne(ctx, bson.M{"id": ID})
	return err
}
