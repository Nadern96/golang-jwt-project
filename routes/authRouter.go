package routes

import (
	"github.com/gin-gonic/gin"
	controllers "github.com/nadern96/golang-jwt-project/controllers"
)

func AuthRoutes(routes *gin.Engine) {
	routes.POST("users/signup", controllers.SignUp())
	routes.POST("users/login", controllers.Login())
}
