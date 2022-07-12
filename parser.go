package ginjwt

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwt"
)

type fetchType int

const (
	Header fetchType = iota
	Url
	Cookie
)

type TokenLookup struct {
	From fetchType
	Name string
}

func (ja *JwtAuthentication) newToken(value interface{}) jwt.Token {
	t := jwt.New()
	t.Set(jwt.IssuedAtKey, time.Now())
	t.Set(ja.IdentityKey, value)
	return t
}

func (ja *JwtAuthentication) getToken(c *gin.Context) (jwt.Token, error) {
	switch ja.TokenLookup.From {
	default:
		return jwt.ParseRequest(
			c.Request,
			jwt.WithHeaderKey(ja.TokenLookup.Name),
			jwt.WithVerify(ja.Algorithm, ja.SecretKey),
		)
	}
}

func (ja *JwtAuthentication) setToken(c *gin.Context, jsonToken []byte) {
	switch ja.TokenLookup.From {
	default:
		c.Header(ja.TokenLookup.Name, ja.TokenHeadName+" "+string(jsonToken))
	}
}
