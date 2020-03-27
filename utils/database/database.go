package database

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"os"
	"reflect"
	"time"
)

var Client *mongo.Client
var Database *mongo.Database
var dbcontext context.Context

func InitDB() {
	client, err := mongo.NewClient(options.Client().ApplyURI(os.Getenv("MONGO_URI")).SetRegistry(
		bson.NewRegistryBuilder().RegisterDecoder(reflect.TypeOf(""), nullawareStrDecoder{}).Build(),
	))
	if err != nil {
		fmt.Println(err)
		return
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	if err := client.Connect(ctx); err != nil {
		fmt.Println(err)
		return
	}

	Client = client
	Database = client.Database(os.Getenv("DB_NAME"))
	dbcontext = ctx
}

func CloseConnection() {
	if err := Client.Disconnect(dbcontext); err != nil {
		fmt.Println(err)
	}
}

func GetCollection(name string) *mongo.Collection {
	if Database == nil || Client.Ping(dbcontext, readpref.SecondaryPreferred()) != nil {
		InitDB()
	}

	return Database.Collection(name)
}
