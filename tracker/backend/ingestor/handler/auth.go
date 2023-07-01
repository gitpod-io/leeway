package handler

import (
	context "context"
	"fmt"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/bufbuild/connect-go"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"

	oidc "github.com/zitadel/oidc/pkg/client"
)

func NewOIDCInterceptor(idp, audience string, allowedSubs []string) (connect.Interceptor, error) {
	cfg, err := oidc.Discover(idp, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		return nil, err
	}
	jwks, err := keyfunc.Get(cfg.JwksURI, keyfunc.Options{
		Ctx: context.Background(),
		RefreshErrorHandler: func(err error) {
			logrus.WithError(err).WithField("identityProvider", idp).Warn("cannot refresh JWKS")
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	})
	if err != nil {
		return nil, err
	}
	logrus.WithField("issuer", idp).WithField("audience", audience).WithField("sub", allowedSubs).Info("enabled OIDC authorisation")

	return connect.UnaryInterceptorFunc(func(uf connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, ar connect.AnyRequest) (connect.AnyResponse, error) {
			rawToken := ar.Header().Get("Authorization")
			if rawToken == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing Authorization header"))
			}
			token, err := jwt.Parse(rawToken, jwks.Keyfunc)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("cannot parse token: %w", err))
			}
			if !token.Valid {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid JWT token"))
			}
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("cannot extract claims from JWT"))
			}
			if !claims.VerifyAudience(audience, true) {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("audience does not match (expected %s, got %s)", audience, claims["aud"]))
			}
			if !claims.VerifyIssuer(idp, true) {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("issuer does not match (expected %s, got %s)", idp, claims["iss"]))
			}
			if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("token has expired"))
			}
			var validSub bool
			for _, sub := range allowedSubs {
				if claims["sub"] == sub {
					validSub = true
					break
				}
			}
			if !validSub {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("unexpected subject %s", claims["sub"]))
			}

			return uf(ctx, ar)
		}
	}), nil
}
