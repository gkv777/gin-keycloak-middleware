package ginkeycloakmiddleware

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/Nerzal/gocloak/v12"
)

type keycloak struct {
	kc     *gocloak.GoCloak
	client string
	secret string
	realm  string
	ctx    context.Context
}

func NewKeycloakClient(ctx context.Context, url, client, secret, realm string) (*keycloak, error) {
	kc := gocloak.NewClient(url)
	kc.RestyClient().SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	// check connection to keycloak server
	if _, err := kc.LoginClient(ctx, client, secret, realm); err != nil {
		return nil, err
	}

	return &keycloak{
		kc:     kc,
		client: client,
		secret: secret,
		realm:  realm,
		ctx:    ctx,
	}, nil	
}

func (k *keycloak) Verify(token string) (*userInfo, error) {
	res, err := k.kc.RetrospectToken(context.Background(), token, k.client, k.secret, k.realm)
	if err != nil {
		return nil, fmt.Errorf("retrospect token error: %s", err.Error())
	}

	if !*res.Active {
		return nil, fmt.Errorf("invalid or expired token")
	}

	t, _, err := k.kc.DecodeAccessToken(context.Background(), token, k.realm)
	if err != nil {
		return nil, fmt.Errorf("decode token error: %s", err.Error())
	}

	ui := getUserInfo(t.Claims)

	return &ui, nil
}

