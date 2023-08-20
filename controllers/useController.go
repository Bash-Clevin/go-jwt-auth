package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Bash-Clevin/go-jwt-auth/db"
	helper "github.com/Bash-Clevin/go-jwt-auth/helpers"
	"github.com/Bash-Clevin/go-jwt-auth/models"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = db.OpenCollection(db.Client, "user")
var validate = validator.New()

func HashPassword()

func VerifyPassword()

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		validationErr := validate.Struct(user)

		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}

		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()

		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error checking email"})
		}

		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "email already exists"})
		}

		user.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.UserId = user.ID.Hex()
		token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, *user.FirstName, *user.LastName, *user.UserType, *&user.UserId)
		user.Token = &token
		user.RefreshToken = &refreshToken

		insertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := fmt.Sprintf("user was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		defer cancel()
		c.JSON(http.StatusOK, insertionNumber)
	}
}

func Login()

func GetUsers()

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("userId")

		if err := helper.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User

		err := userCollection.FindOne(ctx, bson.M{"userId": userId}).Decode(&user)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		c.JSON(http.StatusOK, user)
	}
}
