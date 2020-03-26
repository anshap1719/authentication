package database

import (
	"context"
	"errors"
	"github.com/anshap1719/authentication/controllers/gen/session"
	"github.com/anshap1719/authentication/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

var ErrSessionNotFound = errors.New("No Session found in the database")

type Session struct {
	// The browser and browser version connected with this session
	Browser string `bson:"browser"`
	// The latitude and longitude of the last known location of the session
	Latitude  string `bson:"latitude"`
	Longitude string `bson:"longitude"`

	ID primitive.ObjectID `bson:"_id,omitempty"`
	// The last IP address where this session was used
	IP string `bson:"ip"`

	IsAdmin        bool `bson:"isAdmin"`
	// Whether the session was from a mobile device
	IsMobile bool `bson:"isMobile"`
	// Time that this session was last used
	LastUsed time.Time `bson:"lastUsed"`
	// A human-readable string describing the last known location of the session
	Location string `bson:"location"`
	// The OS of the system where this session was used
	Os string `bson:"os"`
	// ID of the user this session is for
	UserID string `bson:"userId"`
}

func SessionToSession(gen *Session) *session.Session {
	s := &session.Session{
		Browser:   gen.Browser,
		Latitude:  gen.Latitude,
		Longitude: gen.Longitude,
		ID:        gen.ID.Hex(),
		IP:        gen.IP,
		IsMobile:  gen.IsMobile,
		LastUsed:  gen.LastUsed.String(),
		Location:  gen.Location,
		Os:        gen.Os,
		UserID:    gen.UserID,
	}
	return s
}

func CreateSession(ctx context.Context, newSession *Session) (ID string, err error) {
	id := primitive.NewObjectID()
	newSession.ID = id
	if _, err := models.SessionsCollection.InsertOne(ctx, newSession); err != nil {
		return "", err
	}

	return newSession.ID.Hex(), nil
}

func GetSession(ctx context.Context, ID string) (*Session, error) {
	var t Session
	_id, _ := primitive.ObjectIDFromHex(ID)

	res := models.SessionsCollection.FindOne(ctx, bson.M{"_id": _id})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrSessionNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&t); err != nil {
		return nil, err
	}

	return &t, nil
}

func UpdateSession(ctx context.Context, updatedSession *Session) error {
	if _, err := models.SessionsCollection.UpdateOne(ctx, bson.M{"_id": updatedSession.ID}, bson.M{
		"$set": updatedSession,
	}); err == mongo.ErrNoDocuments {
		return ErrSessionNotFound
	} else if err != nil {
		return err
	}

	return nil
}

func DeleteSession(ctx context.Context, ID string) error {
	_id, _ := primitive.ObjectIDFromHex(ID)
	if _, err := models.SessionsCollection.DeleteOne(ctx, bson.M{"_id": _id}); err == mongo.ErrNoDocuments {
		return ErrSessionNotFound
	} else if err != nil {
		return err
	}

	return nil
}

func DeleteSessionMulti(ctx context.Context, IDs []string) error {
	if len(IDs) == 0 {
		return nil
	}

	var returnErr error = nil

	for _, ID := range IDs {
		_id, _ := primitive.ObjectIDFromHex(ID)
		_, err := models.SessionsCollection.DeleteOne(ctx, bson.M{"_id": _id})
		if err != nil {
			returnErr = err
		}
	}

	return returnErr
}

func QuerySessionFromAccount(ctx context.Context, UserID string) ([]*Session, error) {
	var sessions []*Session

	curr, err := models.SessionsCollection.Find(ctx, bson.M{"userId": UserID}, options.Find().SetSort(bson.M{
		"lastUsed": -1,
	}))
	if err == mongo.ErrNoDocuments {
		return nil, ErrSessionNotFound
	} else if err != nil {
		return nil, err
	}

	for curr.Next(ctx) {
		if curr.Err() != nil {
			continue
		}
		var sess Session
		if err := curr.Decode(&sess); err != nil {
			continue
		}

		sessions = append(sessions, &sess)
	}

	return sessions, nil
}

func QuerySessionIds(ctx context.Context, UserID string) ([]string, error) {
	var sessions []Session

	curr, err := models.SessionsCollection.Find(ctx, bson.M{"userId": UserID}, options.Find().SetProjection(bson.M{"_id": 1}))
	if err == mongo.ErrNoDocuments {
		return nil, ErrSessionNotFound
	} else if err != nil {
		return nil, err
	}

	for curr.Next(ctx) {
		if curr.Err() != nil {
			continue
		}
		var sess Session
		if err := curr.Decode(&sess); err != nil {
			continue
		}

		sessions = append(sessions, sess)
	}

	var IDs []string

	for _, sess := range sessions {
		IDs = append(IDs, sess.ID.Hex())
	}

	return IDs, nil
}

func QuerySessionOld(ctx context.Context, LastUsed time.Time) ([]string, error) {
	var sessions []primitive.ObjectID

	curr, err := models.SessionsCollection.Find(ctx, bson.M{"lastUsed": bson.M{"$lt": LastUsed}}, options.Find().SetProjection(bson.M{"_id": 1}))
	if err == mongo.ErrNoDocuments {
		return nil, ErrSessionNotFound
	} else if err != nil {
		return nil, err
	}

	for curr.Next(ctx) {
		if curr.Err() != nil {
			continue
		}
		var sess Session
		if err := curr.Decode(&sess); err != nil {
			continue
		}

		sessions = append(sessions, sess.ID)
	}

	var data []string

	for _, sess := range sessions {
		data = append(data, sess.Hex())
	}

	return data, nil
}
