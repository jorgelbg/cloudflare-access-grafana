// Copyright 2020 Jorge Luis Betancourt <github@jorgelbg.me>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-cmp/cmp"
	"gopkg.in/square/go-jose.v2"
)

var (
	now, _   = time.Parse(time.RFC3339Nano, "2009-11-10T23:00:00Z")
	valid, _ = time.Parse(time.RFC3339Nano, "2009-11-11T00:00:00Z")
)

// utilities for loading JOSE keys.
func loadRSAKey(t *testing.T, filepath string, alg jose.SignatureAlgorithm) *jose.JSONWebKey {
	return loadKey(t, filepath, alg, func(b []byte) (interface{}, error) {
		key, err := x509.ParsePKCS1PrivateKey(b)
		if err != nil {
			return nil, err
		}

		return key.Public(), nil
	})
}

func loadRSAPrivKey(t *testing.T, filepath string, alg jose.SignatureAlgorithm) *jose.JSONWebKey {
	return loadKey(t, filepath, alg, func(b []byte) (interface{}, error) {
		return x509.ParsePKCS1PrivateKey(b)
	})
}

func loadKey(t *testing.T, filepath string, alg jose.SignatureAlgorithm, unmarshal func([]byte) (interface{}, error)) *jose.JSONWebKey {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		t.Fatalf("load file: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("file contained no PEM encoded data: %s", filepath)
	}
	priv, err := unmarshal(block.Bytes)
	if err != nil {
		t.Fatalf("unmarshal key: %v", err)
	}
	key := &jose.JSONWebKey{Key: priv, Use: "sig", Algorithm: string(alg)}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("computing thumbprint: %v", err)
	}
	key.KeyID = hex.EncodeToString(thumbprint)
	return key
}

// staticKeySet implements oidc.KeySet.
type staticKeySet struct {
	keys []*jose.JSONWebKey
}

func (s *staticKeySet) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) == 0 {
		return nil, fmt.Errorf("jwt contained no signatures")
	}
	kid := jws.Signatures[0].Header.KeyID

	for _, key := range s.keys {
		if key.KeyID == kid {
			return jws.Verify(key)
		}
	}

	return nil, fmt.Errorf("no keys matches jwk keyid")
}

type claimsTest struct {
	name       string
	now        time.Time
	signingKey *jose.JSONWebKey
	pubKeys    []*jose.JSONWebKey
	claims     string
	upstream   bool
	fn         func(*testing.T, *http.Request, *httptest.ResponseRecorder)
}

func (c *claimsTest) run(t *testing.T) {
	cfg := &Config{
		AuthDomain:    "https://your-own.cloudflareaccess.com",
		PolicyAUD:     "my-policy-aud",
		ForwardHeader: "X-WEBAUTH-USER",
		ForwardHost:   "localhost:3000",
		ListenAddr:    ":3002",
	}

	config := &oidc.Config{
		ClientID: "my-policy-aud",
		Now:      func() time.Time { return c.now },
	}
	verifier := oidc.NewVerifier(
		"https://your-own.cloudflareaccess.com",
		&staticKeySet{
			keys: c.pubKeys,
		},
		config,
	)

	// Sign and serialize the claims in a JWT.
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(c.signingKey.Algorithm),
		Key:       c.signingKey,
	}, nil)
	if err != nil {
		t.Fatalf("initialize signer: %v", err)
	}

	jws, err := signer.Sign([]byte(c.claims))
	if err != nil {
		t.Fatalf("sign claims: %v", err)
	}

	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize token: %v", err)
	}

	upstream := false
	rr := httptest.NewRecorder()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream = true
		if c.fn != nil {
			c.fn(t, r, rr)
		}
	})

	req := httptest.NewRequest("GET", "http://domain.com", nil)
	if c.claims != "" {
		req.Header.Add(CFJWTHeader, token)
	}

	VerifyToken(next, verifier, cfg).ServeHTTP(rr, req)

	if c.upstream != upstream {
		t.Fatalf("Forward to upstream got: %t, want: %t", upstream, c.upstream)
	}

	// We do not expect the upstream to be called so the VerifyToken middleware must have sent a
	// reply back.
	if c.upstream == false && c.fn != nil {
		c.fn(t, req, rr)
	}
}

func TestVerifierMiddleware(t *testing.T) {
	tests := []claimsTest{
		{
			name:       "valid token",
			now:        now,
			signingKey: loadRSAPrivKey(t, "testdata/rsa_1.pem", jose.RS256),
			pubKeys: []*jose.JSONWebKey{
				loadRSAKey(t, "testdata/rsa_1.pem", jose.RS256),
			},
			claims: fmt.Sprintf(`{
				"iss": "https://your-own.cloudflareaccess.com",
				"aud": "my-policy-aud",
				"email": "test@example.com",
				"type": "app",
				"exp": %d
			}`, valid.Unix()),
			upstream: true,
			fn: func(t *testing.T, r *http.Request, rr *httptest.ResponseRecorder) {
				email := r.Header.Get("X-WEBAUTH-USER")
				if diff := cmp.Diff(email, "test@example.com"); diff != "" {
					t.Errorf("Wrong user was authenticated (-want +got):\n%s", diff)
				}
			},
		},
		{
			name:       "expired token",
			now:        now.Add(24 * time.Hour),
			signingKey: loadRSAPrivKey(t, "testdata/rsa_1.pem", jose.RS256),
			pubKeys: []*jose.JSONWebKey{
				loadRSAKey(t, "testdata/rsa_1.pem", jose.RS256),
			},
			claims: fmt.Sprintf(`{
				"iss": "https://your-own.cloudflareaccess.com",
				"aud": "my-policy-aud",
				"email": "test@example.com",
				"type": "app",
				"exp": %d
			}`, valid.Unix()),
			upstream: false,
			fn: func(t *testing.T, r *http.Request, rr *httptest.ResponseRecorder) {
				expected := `Invalid token: oidc: token is expired (Token Expiry: 2009-11-11 01:00:00 +0100 CET)`
				if diff := cmp.Diff(expected, rr.Body.String()); diff != "" {
					t.Errorf("Wrong user was authenticated (-want +got):\n%s", diff)
				}
			},
		},
		{
			name:       "invalid token",
			now:        now,
			signingKey: loadRSAPrivKey(t, "testdata/rsa_1.pem", jose.RS256),
			pubKeys: []*jose.JSONWebKey{
				loadRSAKey(t, "testdata/rsa_1.pem", jose.RS256),
			},
			claims: fmt.Sprintf(`{
				"iss": "https://another-domain.cloudflareaccess.com",
				"aud": "my-policy-aud",
				"email": "test@example.com",
				"type": "app",
				"exp": %d
			}`, valid.Unix()),
			upstream: false,
			fn: func(t *testing.T, r *http.Request, rr *httptest.ResponseRecorder) {
				expected := `Invalid token: oidc: id token issued by a different provider, expected "https://your-own.cloudflareaccess.com" got "https://another-domain.cloudflareaccess.com"`
				if diff := cmp.Diff(expected, rr.Body.String()); diff != "" {
					t.Errorf("Wrong user was authenticated (-want +got):\n%s", diff)
				}
			},
		},
		{
			name:       "empty claim",
			now:        now,
			signingKey: loadRSAPrivKey(t, "testdata/rsa_1.pem", jose.RS256),
			pubKeys: []*jose.JSONWebKey{
				loadRSAKey(t, "testdata/rsa_1.pem", jose.RS256),
			},
			claims:   "",
			upstream: false,
			fn:       nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}
