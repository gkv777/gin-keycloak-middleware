package ginkeycloakmiddleware

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

const (
	CtxLogin = "user_login"
	CtxRoles = "user_roles"
	CtxEmail = "user_email"
	CtxFName = "user_fname"
	CtxLName = "user_lname"
)

type userInfo struct {
	Login string
	FName string
	LName string
	Email string
	Roles []string
}

func getUserInfo(tc jwt.Claims) userInfo {
	claims, _ := tc.(jwt.MapClaims)
	realm_access := claims["realm_access"].(map[string]interface{})
	roles_interfaces := realm_access["roles"].([]interface{})

	roles := make([]string, 0, len(roles_interfaces))
	for _, ri := range roles_interfaces {
		roles = append(roles, ri.(string))
	}

	r := userInfo{
		Login: claims["preferred_username"].(string),
		FName: claims["given_name"].(string),
		LName: claims["family_name"].(string),
		Email: claims["email"].(string),
		Roles: roles,
	}
	return r
}

func (ui userInfo)SaveToContext(c *gin.Context) {
	c.Set(CtxLogin, ui.Login)
	c.Set(CtxFName, ui.FName)
	c.Set(CtxLName, ui.LName)
	c.Set(CtxEmail, ui.Email)
	c.Set(CtxRoles, ui.Roles)
}