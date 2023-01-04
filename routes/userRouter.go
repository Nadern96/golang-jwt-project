package routes

import (
	"github.com/gin-gonic/gin"
	controllers "github.com/nadern96/golang-jwt-project/controllers"
	middleware "github.com/nadern96/golang-jwt-project/middlewares"
)

func UserRoutes(routes *gin.Engine) {
	routes.Use(middleware.Authenticate())
	routes.GET("users/", controllers.GetUsers())
	routes.GET("users/:id", controllers.GetUser())
}
