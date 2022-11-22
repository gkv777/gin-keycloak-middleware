package ginkeycloakmiddleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

var (
	ErrNoAuthHeader = errors.New("authorization information is missing from the request")
	ErrNoBearer     = errors.New("bearer token is missing from the request")
)

type AuthKeycloakMiddleware struct {
	keycloak *keycloak
}

func NewAuthKeycloakMiddleware(url, client, secret, realm string) (*AuthKeycloakMiddleware, error) {
	k, err := NewKeycloakClient(context.Background(), url, client, secret, realm)
	if err != nil {
		return nil, err
	}

	return &AuthKeycloakMiddleware{
		keycloak: k,
	}, nil
}

func (m *AuthKeycloakMiddleware) abort(c *gin.Context, status int, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"message": msg})
}

func (m *AuthKeycloakMiddleware) Check(auth bool, role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !auth {
			c.Next()
			return
		}

		s := strings.SplitN(c.Request.Header.Get("Authorization"), " ", 2)
		if len(s) != 2 || s[0] != "Bearer" {
			m.abort(c, http.StatusUnauthorized, "Authorization token is not found")
			return
		}

		ui, err := m.keycloak.Verify(s[1])
		if err != nil {
			m.abort(c, http.StatusUnauthorized, err.Error())
			return
		}

		for _, r := range ui.Roles {
			if r == role {
				ui.SaveToContext(c)
				c.Next()
				return
			}
		}
		m.abort(c, http.StatusForbidden, "Access Deny")
	}
}
