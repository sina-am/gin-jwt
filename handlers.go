package ginjwt

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwt"
)

func (ja *JwtAuthentication) LoginHandler(c *gin.Context) {
	data, err := ja.Authenticator(c)
	if err != nil {
		c.AbortWithError(http.StatusForbidden, err)
	}
	token, err := jwt.Sign(ja.newToken(data), ja.Algorithm, ja.SecretKey)
	if err != nil {
		c.AbortWithError(http.StatusUnauthorized, err)
	}
	ja.setToken(c, token)
}
