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
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/kelseyhightower/envconfig"
)

const (
	// CFJWTHeader is the header key set by Cloudflare Access after a successful authentication
	CFJWTHeader = "Cf-Access-Jwt-Assertion"
)

// CloudflareClaim holds the claims about the End-User/Authentication event.
type CloudflareClaim struct {
	Email string `json:"email"`
	Type  string `json:"type"`
}

// Config is the general configuration (read from environment variables)
type Config struct {
	AuthDomain    string
	PolicyAUD     string
	ForwardHeader string
	ForwardHost   string
	ListenAddr    string `envconfig:"ADDR"`
}

var (
	ctx = context.Background()
)

// VerifyToken is a middleware to verify a CF Access token
func VerifyToken(next http.Handler, tokenVerifier *oidc.IDTokenVerifier, cfg *Config) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		headers := r.Header

		// Make sure that the incoming request has our token header
		// Could also look in the cookies for CF_AUTHORIZATION
		accessJWT := headers.Get(CFJWTHeader)
		if accessJWT == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("No token on the request"))
			return
		}

		// Verify the access token
		ctx := r.Context()
		token, err := tokenVerifier.Verify(ctx, accessJWT)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("Invalid token: %s", err.Error())))
			return
		}

		// Extract custom claims
		var claims CloudflareClaim
		if err := token.Claims(&claims); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("Invalid claims in token: %s", err.Error())))
		}

		// set the authentication forward header before proxying the request
		r.Header.Add(cfg.ForwardHeader, claims.Email)
		log.Printf("Authenticated as: %s", claims.Email)

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func main() {
	var cfg Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		log.Fatal(err.Error())
	}

	var (
		certsURL = fmt.Sprintf("%s/cdn-cgi/access/certs", cfg.AuthDomain)

		config = &oidc.Config{
			ClientID: cfg.PolicyAUD,
		}
		keySet   = oidc.NewRemoteKeySet(ctx, certsURL)
		verifier = oidc.NewVerifier(cfg.AuthDomain, keySet, config)
	)

	director := func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", "cloudflare-access-proxy")
		// TODO: should we trust on the Schema of the original request?
		req.URL.Scheme = "http"

		if len(strings.TrimSpace(cfg.ForwardHost)) > 0 {
			req.URL.Host = cfg.ForwardHost
		}
	}

	proxy := &httputil.ReverseProxy{Director: director}
	http.Handle("/", VerifyToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}), verifier, &cfg))

	log.Printf("Listening on %s", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, nil); err != nil {
		log.Fatalf("Unable to start server on [%s], error: %s", cfg.ListenAddr, err.Error())
	}
}
