package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwa"
	ginjwt "github.com/sina-am/gin-jwt"
)

type User struct {
	ID       string
	Username string
	Password string
}

type UserAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var UserStorage = []User{
	{ID: "1", Username: "admin", Password: "admin"},
	{ID: "2", Username: "test", Password: "test"},
}

func GetUserById(userID string) (User, error) {
	for i := 0; i < len(UserStorage); i++ {
		if userID == UserStorage[i].ID {
			return UserStorage[i], nil
		}
	}
	return User{}, nil
}
func GetUser(username, password string) (User, error) {
	for i := 0; i < len(UserStorage); i++ {
		if username == UserStorage[i].Username && password == UserStorage[i].Password {
			return UserStorage[i], nil
		}
	}
	return User{}, nil
}

func main() {
	authMiddleware := ginjwt.JwtAuthentication{
		Authenticator: func(c *gin.Context) (interface{}, error) {
			form := UserAuth{}
			if err := c.ShouldBindJSON(&form); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"Error": "Bad request"})
				return nil, err
			}
			user, err := GetUser(form.Username, form.Password)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"Error": "Login failed"})
				return nil, err
			}
			return user.ID, nil
		},
		Authorizator: func(data interface{}) (interface{}, error) {
			return GetUserById(data.(string))
		},
		SecretKey:   []byte("randomkey"),
		Algorithm:   jwa.HS512,
		IdentityKey: "user",
		TokenLookup: ginjwt.TokenLookup{From: ginjwt.Cookie, Name: "jwt"},
	}

	r := gin.Default()
	r.Use(authMiddleware.AuthenticationMiddleware())
	r.POST("/login/", authMiddleware.LoginHandler)

	authorized := r.Group("/user", authMiddleware.LoginRequiredMiddleware(gin.H{"Message": "Permission denied"}))
	authorized.GET("/profile/", Profile)
	r.Run()
}

func Profile(c *gin.Context) {
	isAuthenticated := c.GetBool("IsAuthenticated")
	if isAuthenticated {
		user, _ := c.Get("user")
		c.JSON(http.StatusOK, gin.H{"User": user.(User)})
	} else {
		c.JSON(http.StatusOK, gin.H{"Failed": "No such user"})
	}
}
