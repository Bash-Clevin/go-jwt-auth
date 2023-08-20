package routes

import (
	controller "github.com/Bash-Clevin/go-jwt-auth/controllers"
	"github.com/Bash-Clevin/go-jwt-auth/middleware"
	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenitcate())
	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.GET("/users/:user_id", controller.GetUser())
}
