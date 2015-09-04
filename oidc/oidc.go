package oidc

import (
	"errors"
	"github.com/coreos/go-oidc/jose"
	gooidc "github.com/coreos/go-oidc/oidc"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

type oidcAccess struct {
	jwt jose.JWT
}

// Returns an object that satisfies the gRPC credentials.Credentials interface.
// This should be used for adding an arbitrary ODIC authentication information to
// gRPC requests.
// See https://github.com/grpc/grpc-go/blob/master/grpc-auth-support.md for more examples.
func NewOIDCAccess(token *jose.JWT) credentials.Credentials {
	return oidcAccess{jwt: *token}

}
func (ja oidcAccess) GetRequestMetadata(ctx context.Context) (map[string]string, error) {
	return map[string]string{
		"jwt": ja.jwt.Encode(),
	}, nil
}

// Reads the OIDC JWT passed in the context and verifies it using the given OIDC client.
// Returns the verified identity on success, error otherwise.
func VerifiedIdentityFromContext(client *gooidc.Client, ctx context.Context) (*gooidc.Identity, error) {
	md, ok := metadata.FromContext(ctx)
	if !ok {
		return nil, errors.New("missing RPC credentials")
	}
	rawJWT, ok := md["jwt"]
	if !ok {
		return nil, errors.New("missing OIDC credentials")
	}
	if len(rawJWT) != 1 {
		return nil, errors.New("incorrect JWT data sent")
	}
	jwt, err := jose.ParseJWT(rawJWT[0])
	if err != nil {
		return nil, err
	}
	if err := client.VerifyJWT(jwt); err != nil {
		return nil, err
	}
	claims, err := jwt.Claims()
	if err != nil {
		return nil, err
	}
	return gooidc.IdentityFromClaims(claims)
}
