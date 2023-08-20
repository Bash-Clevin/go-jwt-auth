package middleware

import (
	"net/http"

	helper "github.com/Bash-Clevin/go-jwt-auth/helpers"
	"github.com/gin-gonic/gin"
)

func Authenitcate() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientToken := c.Request.Header.Get("token")

		if clientToken == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No authorization header"})
			c.Abort()
			return
		}

		claims, err := helper.ValidateToken(clientToken)
		if err != "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Auth Error"})
			c.Abort()
			return
		}
		c.Set("email", claims.Email)
		c.Set("firstName", claims.FirstName)
		c.Set("lastName", claims.LastName)
		c.Set("uid", claims.Uid)
		c.Set("userType", claims.UserType)
		c.Next()
	}
}
