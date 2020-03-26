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
	"strings"
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

func PrepareFilters(filters string) map[string]interface{} {
	var filterTypes []string
	var filtersListOfEachType = make(map[string]interface{})
	filterTypes = strings.Split(filters, ", ")
	if len(filterTypes) == 1 {
		filterTypes = strings.Split(filters, ",")
	}

	for _, v := range filterTypes {
		if string(v[0]) == " " {
			strings.TrimSpace(v)
		}
		d := strings.Split(v, ":")
		if string(d[1][0]) == "-" {
			filtersListOfEachType[d[0]] = map[string]string{"$ne": d[1][1:]}
		} else {
			filtersListOfEachType[d[0]] = d[1]
		}
	}
	return filtersListOfEachType
}
