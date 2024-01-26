package helpers

import (
	"context"
	"log"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/joshua468/go-jwt-project/database"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type SignedDetails struct {
	Email      string
	First_name string
	Last_name  string
	Uid        string
	User_type  string
	jwt.StandardClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var SECRET_KEY = os.Getenv("YOUR_SECRET_KEY")

func GenerateAllTokens(email string, firstName string, lastName string, userType string, uid string) (SignedToken string, SignedRefreshToken string, err error) {
	claims := &SignedDetails{
		Email:      email,
		First_name: firstName,
		Last_name:  lastName,
		Uid:        uid,
		User_type:  userType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * 24).Unix(),
		},
	}
	refreshClaims := &SignedDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * 168).Unix(),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))

	if err != nil {
		log.Panic(err)
		return "", "", err
	}
	return token, refreshToken, err
}

func ValidateToken(SignedToken string) (claims *SignedDetails, msg string, err error) {
	token, err := jwt.ParseWithClaims(
		SignedToken,
		&SignedDetails{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil
		},
	)
	if err != nil {
		msg = err.Error()
		return nil, msg, err
	}
	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		msg = "The token is invalid"
		return nil, msg, err
	}
	if claims.ExpiresAt < time.Now().Local().Unix() {
		msg = "Token is expired"
		return claims, msg, err
	}
	return claims, msg, err
}

func UpdateAllTokens(signedToken string, signedRefreshToken string, userId string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var updateObj primitive.D
	updateObj = append(updateObj, bson.E{"token", signedToken})
	updateObj = append(updateObj, bson.E{"refresh_token", signedRefreshToken})
	UpdatedAt, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	updateObj = append(updateObj, bson.E{"updated_at", UpdatedAt})

	upsert := true
	filter := bson.M{"user_id": userId}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	_, err := userCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{"$set", updateObj},
		},
		&opt,
	)

	if err != nil {
		log.Panic(err)
		return err
	}
	return nil
}
