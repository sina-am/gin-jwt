package ginjwt

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (ja *JwtAuthentication) AuthenticationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("IsAuthenticated", false)
		c.Set(ja.IdentityKey, nil)

		token, err := ja.getToken(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"Message": "Invalid header"})
		}
		if tokenValue, ok := token.Get(ja.IdentityKey); ok {
			user, err := ja.Authorizator(tokenValue)
			if err == nil {
				c.Set("IsAuthenticated", true)
				c.Set(ja.IdentityKey, user)
			}
		}
	}
}

func (ja *JwtAuthentication) LoginRequiredMiddleware(errorMessage gin.H) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !c.GetBool("IsAuthenticated") {
			c.AbortWithStatusJSON(http.StatusForbidden, errorMessage)
		}
	}
}
