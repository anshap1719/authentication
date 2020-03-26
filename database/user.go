package database

import (
	"context"
	"errors"
	"github.com/anshap1719/authentication/controllers/gen/instagram"
	"github.com/anshap1719/authentication/controllers/gen/user"
	"github.com/anshap1719/authentication/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
)

var ErrUserNotFound = errors.New("No User found in the database")
var ErrEmailVerificationNotFound = errors.New("No EmailVerification found in the database")
var ErrPhoneVerificationNotFound = errors.New("No PhoneVerification found in the database")

type EmailVerification struct {
	Email string `bson:"email"`

	ID string `bson:"id"`

	TimeExpires time.Time `bson:"timeExpires"`

	UserID string `bson:"userId"`
}

type PhoneVerification struct {
	ID primitive.ObjectID `bson:"_id,omitempty"`

	Country string `bson:"country"`

	Phone string `bson:"phone"`

	OTP string `bson:"otp"`

	TimeExpires time.Time `bson:"timeExpires"`

	UserID string `bson:"userId"`
}

func CreateUser(ctx context.Context, newUser *models.User) (ID string, err error) {
	userID := primitive.NewObjectID()
	newUser.ID = userID

	if _, err := models.UsersCollection.InsertOne(ctx, newUser); err != nil {
		return "", err
	}

	return userID.Hex(), nil
}

func GetUser(ctx context.Context, ID string) (*models.User, error) {
	var t models.User

	_id, _ := primitive.ObjectIDFromHex(ID)

	if res := models.UsersCollection.FindOne(ctx, bson.M{
		"_id": _id,
	}); res.Err() == mongo.ErrNoDocuments {
		return nil, ErrUserNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	} else {
		if err := res.Decode(&t); err != nil {
			return nil, err
		}
	}

	return &t, nil
}

func GetUserMulti(ctx context.Context, IDs []string) ([]*models.User, error) {
	if len(IDs) == 0 {
		return nil, nil
	}

	var returnErr error
	var data []*models.User
	var objIds = []primitive.ObjectID{}

	for _, id := range IDs {
		objId, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			continue
		}
		objIds = append(objIds, objId)
	}

	curr, err := models.UsersCollection.Find(ctx, bson.M{
		"_id": bson.M{
			"$in": objIds,
		},
	})
	if err != nil {
		return nil, err
	}

	for curr.Next(ctx) {
		if curr.Err() != nil {
			continue
		}

		var usr models.User

		if err := curr.Decode(&usr); err != nil {
			continue
		}

		data = append(data, &usr)
	}

	return data, returnErr
}

//func GetAllUsers() ([]models.User, error) {
//	var user []models.User
//
//	if err := models.UsersCollection.Find(bson.M{}).All(&user); err != nil {
//		return nil, err
//	}
//
//	return user, nil
//}

func UpdateUser(ctx context.Context, updatedUser *models.User) error {
	if _, err := models.UsersCollection.UpdateOne(ctx, bson.M{"_id": updatedUser.ID}, bson.M{
		"$set": updatedUser,
	}); err == mongo.ErrNoDocuments {
		return ErrUserNotFound
	} else if err != nil {
		return err
	}

	return nil
}

func CreateEmailVerification(ctx context.Context, newEmailVerification *EmailVerification) error {
	if _, err := models.EmailVerificationCollection.InsertOne(ctx, newEmailVerification); err != nil {
		return err
	}

	// @TODO: Send Email For Verifying User's Email Using The EmailVerification Data

	return nil
}

func GetEmailVerification(ctx context.Context, ID string) (*EmailVerification, error) {
	var ev EmailVerification

	oid, err := primitive.ObjectIDFromHex(ID);
	if err != nil {
		return nil, err
	}

	res := models.EmailVerificationCollection.FindOne(ctx, bson.M{"_id": oid})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrEmailVerificationNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&ev); err != nil {
		return nil, err
	}

	return &ev, nil
}

func DeleteEmailVerification(ctx context.Context, ID string) error {
	oid, err := primitive.ObjectIDFromHex(ID);
	if err != nil {
		return err
	}

	_, err = models.EmailVerificationCollection.DeleteOne(ctx, bson.M{"_id": oid})
	return err
}

func CreatePhoneVerification(ctx context.Context, pv *PhoneVerification) error {
	if _, err := models.PhoneVerificationCollection.InsertOne(ctx, pv); err != nil {
		return err
	}

	return nil
}

func UpdatePhoneVerification(ctx context.Context, pv *PhoneVerification) error {
	if _, err := models.PhoneVerificationCollection.UpdateOne(ctx, bson.M{
		"phone": pv.Phone,
	}, bson.M{
		"$set": pv,
	}); err != nil {
		return err
	}

	return nil
}

func GetPhoneVerification(ctx context.Context, ID string) (*PhoneVerification, error) {
	var ev PhoneVerification

	oid, err := primitive.ObjectIDFromHex(ID);
	if err != nil {
		return nil, err
	}

	res := models.PhoneVerificationCollection.FindOne(ctx, bson.M{"_id": oid})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrPhoneVerificationNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&ev); err != nil {
		return nil, err
	}

	return &ev, nil
}

func DeletePhoneVerification(ctx context.Context, ID string) error {
	oid, err := primitive.ObjectIDFromHex(ID);
	if err != nil {
		return err
	}

	_, err = models.PhoneVerificationCollection.DeleteOne(ctx, bson.M{"_id": oid})
	return err
}

func QueryEmailVerificationByUserID(ctx context.Context, UserID string) (*EmailVerification, error) {
	var ev EmailVerification

	res := models.EmailVerificationCollection.FindOne(ctx, bson.M{"userId": UserID})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrEmailVerificationNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&ev); err != nil {
		return nil, err
	}

	return &ev, nil
}

func QueryPhoneVerificationByUserID(ctx context.Context, UserID string) (*PhoneVerification, error) {
	var ev PhoneVerification

	res := models.PhoneVerificationCollection.FindOne(ctx, bson.M{"userId": UserID})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrEmailVerificationNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&ev); err != nil {
		return nil, err
	}

	return &ev, nil
}

func QueryUserEmail(ctx context.Context, Email string) (*models.User, error) {
	var usr models.User

	res := models.UsersCollection.FindOne(ctx, bson.M{"email": Email})
	if res.Err() == mongo.ErrNoDocuments {
		return nil, ErrUserNotFound
	} else if res.Err() != nil {
		return nil, res.Err()
	}

	if err := res.Decode(&usr); err != nil {
		return nil, err
	}

	return &usr, nil
}

//func QueryPasswordLoginFromIDWithBody(ctx context.Context, UserID string) (*PasswordLogin, error) {
//	var pl PasswordLogin
//
//	if err := models.PasswordLoginCollection.Find(bson.M{"userId": UserID}).One(&pl); err == mgo.ErrNotFound {
//		return nil, ErrPasswordLoginNotFound
//	} else if err != nil {
//		return nil, err
//	}
//
//	return &pl, nil
//}

func UserToUser(gen *models.User) *user.UserMedia {
	updated := gen.UpdatedAt.String()
	created := gen.CreatedAt.String()

	s := &user.UserMedia{
		ChangingEmail:      &gen.ChangingEmail,
		Email:              gen.Email,
		FirstName:          gen.FirstName,
		ID:                 gen.ID.Hex(),
		IsAdmin:            &gen.IsAdmin,
		LastName:           gen.LastName,
		VerifiedEmail:      gen.VerifiedEmail,
		UpdatedAt:          &updated,
		IsActive:           &gen.IsActive,
		CreatedAt:          &created,
	}
	return s
}

func UserToInstagramUser(gen *models.User) *instagram.UserMedia {
	updated := gen.UpdatedAt.String()
	created := gen.CreatedAt.String()

	s := &instagram.UserMedia{
		ChangingEmail:      &gen.ChangingEmail,
		Email:              gen.Email,
		FirstName:          gen.FirstName,
		ID:                 gen.ID.Hex(),
		IsAdmin:            &gen.IsAdmin,
		LastName:           gen.LastName,
		VerifiedEmail:      gen.VerifiedEmail,
		UpdatedAt:          &updated,
		IsActive:           &gen.IsActive,
		CreatedAt:          &created,
	}
	return s
}

func UserFromUserParamsMerge(from *user.UserUpdateParams, to *models.User) *models.User {
	if from.Email != nil {
		to.Email = *from.Email
	}

	if from.FirstName != nil {
		to.FirstName = *from.FirstName
	}

	if from.LastName != nil {
		to.LastName = *from.LastName
	}

	if from.ChangingEmail != nil {
		to.ChangingEmail = *from.ChangingEmail
	}

	if from.IsAdmin != nil {
		to.IsAdmin = *from.IsAdmin
	}

	if from.VerifiedEmail != nil {
		to.VerifiedEmail = *from.VerifiedEmail
	}

	return to
}
