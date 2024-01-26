// routes/authRouter.go

package routes

import (
	"github.com/gin-gonic/gin"
	controller "github.com/joshua468/go-jwt-project/controllers"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("users/Signup", controller.Signup())
	incomingRoutes.POST("users/Login", controller.Login())
}
