package ginjwt

import (
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

type JwtAuthentication struct {
	Authenticator func(c *gin.Context) (interface{}, error)
	Authorizator  func(data interface{}) (interface{}, error)
	SecretKey     interface{}
	Algorithm     jwa.SignatureAlgorithm
	IdentityKey   string
	TokenLookup   TokenLookup
	TokenHeadName string
}

type JwtAuthMiddleware interface {
	AuthenticationMiddleware() gin.HandlerFunc
	LoginRequiredMiddleware() gin.HandlerFunc
	LoginHandler()

	newToken(value interface{}) jwt.Token
	getToken(c *gin.Context) (jwt.Token, error)
	setToken(c *gin.Context, jsonToken []byte)
}
