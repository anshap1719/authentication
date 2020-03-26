package models

import (
	"github.com/anshap1719/authentication/utils/database"
	"go.mongodb.org/mongo-driver/mongo"
)

var PasswordLoginCollection *mongo.Collection
var UsersCollection *mongo.Collection
var ResetPasswordCollection *mongo.Collection
var FacebookAccountCollection *mongo.Collection
var FacebookRegisterCollection *mongo.Collection
var FacebookConnectionCollection *mongo.Collection
var InstagramAccountCollection *mongo.Collection
var InstagramRegisterCollection *mongo.Collection
var InstagramConnectionCollection *mongo.Collection
var TwitterAccountCollection *mongo.Collection
var TwitterRegisterCollection *mongo.Collection
var TwitterConnectionCollection *mongo.Collection
var TwitterTokenCollection *mongo.Collection
var GoogleAccountCollection *mongo.Collection
var GoogleRegisterCollection *mongo.Collection
var GoogleConnectionCollection *mongo.Collection
var LinkedinAccountCollection *mongo.Collection
var LinkedinRegisterCollection *mongo.Collection
var LinkedinConnectionCollection *mongo.Collection
var SessionsCollection *mongo.Collection
var LoginTokenCollection *mongo.Collection
var MergeTokenCollection *mongo.Collection
var EmailVerificationCollection *mongo.Collection
var PhoneVerificationCollection *mongo.Collection

func InitCollections() {
	PasswordLoginCollection = database.GetCollection("PasswordLogin")
	UsersCollection = database.GetCollection("Users")
	ResetPasswordCollection = database.GetCollection("ResetPassword")
	FacebookAccountCollection = database.GetCollection("FacebookAccount")
	FacebookConnectionCollection = database.GetCollection("FacebookConnection")
	FacebookRegisterCollection = database.GetCollection("FacebookRegister")
	InstagramAccountCollection = database.GetCollection("InstagramAccount")
	InstagramConnectionCollection = database.GetCollection("InstagramConnection")
	InstagramRegisterCollection = database.GetCollection("InstagramRegister")
	TwitterAccountCollection = database.GetCollection("TwitterAccount")
	TwitterConnectionCollection = database.GetCollection("TwitterConnection")
	TwitterRegisterCollection = database.GetCollection("TwitterRegister")
	TwitterTokenCollection = database.GetCollection("TwitterToken")
	GoogleAccountCollection = database.GetCollection("GoogleAccount")
	GoogleConnectionCollection = database.GetCollection("GoogleConnection")
	GoogleRegisterCollection = database.GetCollection("GoogleRegister")
	LinkedinAccountCollection = database.GetCollection("LinkedinAccount")
	LinkedinConnectionCollection = database.GetCollection("LinkedinConnection")
	LinkedinRegisterCollection = database.GetCollection("LinkedinRegister")
	SessionsCollection = database.GetCollection("Sessions")
	LoginTokenCollection = database.GetCollection("LoginToken")
	MergeTokenCollection = database.GetCollection("MergeToken")
	EmailVerificationCollection = database.GetCollection("EmailVerification")
	PhoneVerificationCollection = database.GetCollection("PhoneVerification")
}
