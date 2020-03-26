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

var ErrLoginTokenNotFound = errors.New("No Login Token found in the database")

type LoginToken struct {
	TimeExpire time.Time `bson:"timeExpire"`

	Token uuid.UUID `bson:"token"`

	UserID string `bson:"userId"`
}

type MergeToken struct {
	TimeExpire time.Time `bson:"timeExpire"`

	Token uuid.UUID `bson:"token"`

	UserID string `bson:"userId"`
}

func CreateLoginToken(ctx context.Context, newLoginToken *LoginToken) (Token uuid.UUID, err error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	newLoginToken.Token = uid

	if _, err := models.LoginTokenCollection.InsertOne(ctx, newLoginToken); err != nil {
		return uuid.Nil, err
	}

	return newLoginToken.Token, nil
}

func GetLoginToken(ctx context.Context, Token uuid.UUID) (*LoginToken, error) {
	var lt LoginToken

	res := models.LoginTokenCollection.FindOne(ctx, bson.M{"token": Token})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrLoginTokenNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&lt); err != nil {
		return nil, err
	}

	return &lt, nil
}

func DeleteLoginToken(ctx context.Context, Token uuid.UUID) error {
	_, err := models.LoginTokenCollection.DeleteOne(ctx, bson.M{"token": Token})
	return err
}

func DeleteLoginTokenMulti(ctx context.Context, Tokens []uuid.UUID) error {
	if len(Tokens) == 0 {
		return nil
	}

	var returnErr error

	for _, Token := range Tokens {
		if _, err := models.LoginTokenCollection.DeleteOne(ctx, bson.M{"token": Token}); err != nil {
			returnErr = err
		}
	}

	return returnErr
}

func QueryLoginTokenOld(ctx context.Context, TimeExpire time.Time) ([]uuid.UUID, error) {
	var lts []LoginToken

	curr, err := models.LoginTokenCollection.Find(ctx, bson.M{"timeExpire": bson.M{"$lt": TimeExpire}})
	if err == mongo.ErrNoDocuments {
		return nil, ErrLoginTokenNotFound
	} else if err != nil {
		return nil, err
	}

	for curr.Next(ctx) {
		if curr.Err() != nil {
			continue
		}
		var lt LoginToken
		if err := curr.Decode(&lt); err != nil {
			continue
		}

		lts = append(lts, lt)
	}

	var data []uuid.UUID

	for _, token := range lts {
		data = append(data, token.Token)
	}

	return data, nil
}

func CreateMergeToken(ctx context.Context, newMergeToken *MergeToken) (Token uuid.UUID, err error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	newMergeToken.Token = uid

	if _, err := models.MergeTokenCollection.InsertOne(ctx, newMergeToken); err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}

func GetMergeToken(ctx context.Context, Token uuid.UUID) (*MergeToken, error) {
	var t MergeToken
	res := models.MergeTokenCollection.FindOne(ctx, bson.M{"token": Token})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrMergeTokenNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&t); err != nil {
		return nil, err
	}

	return &t, nil
}

func DeleteMergeToken(ctx context.Context, Token uuid.UUID) error {
	_, err := models.MergeTokenCollection.DeleteOne(ctx, bson.M{"token": Token})
	return err
}

func DeleteMergeTokenMulti(ctx context.Context, Tokens []uuid.UUID) error {
	if len(Tokens) == 0 {
		return nil
	}

	var returnErr error

	for _, token := range Tokens {
		if _, err := models.MergeTokenCollection.DeleteOne(ctx, bson.M{"token": token}); err != nil {
			returnErr = err
		}
	}

	return returnErr
}

func QueryMergeTokenOld(ctx context.Context, TimeExpire time.Time) ([]uuid.UUID, error) {
	var tokens []uuid.UUID

	curr, err := models.MergeTokenCollection.Find(ctx, bson.M{"timeExpire": bson.M{"$lt": TimeExpire}}, options.Find().SetProjection(bson.M{"token": 1}))
	if err == mongo.ErrNoDocuments {
		return nil, ErrMergeTokenNotFound
	} else if err != nil {
		return nil, err
	}

	for curr.Next(ctx) {
		if curr.Err() != nil {
			continue
		}
		var token MergeToken
		if err := curr.Decode(&token); err != nil {
			continue
		}

		tokens = append(tokens, token.Token)
	}

	return tokens, nil
}
