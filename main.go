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
	"os"
	"strings"

	"github.com/coreos/go-oidc"
)

var (
	ctx        = context.TODO()
	authDomain = os.Getenv("AUTHDOMAIN")
	certsURL   = fmt.Sprintf("%s/cdn-cgi/access/certs", authDomain)

	// policyAUD is your application AUD value
	policyAUD = os.Getenv("POLICYAUD")

	// forwardHeader is the header to be set from the email claim embedded in the JWT token
	forwardHeader = os.Getenv("FORWARDHEADER")

	// forwardHost is the host to bet used to forward the request. If set it will override the Host
	// header of the original request
	forwardHost = os.Getenv("FORWARDHOST")

	// listenAddr is the port where this proxy will be listening
	listenAddr = os.Getenv("ADDR")

	config = &oidc.Config{
		ClientID: policyAUD,
	}
	keySet   = oidc.NewRemoteKeySet(ctx, certsURL)
	verifier = oidc.NewVerifier(authDomain, keySet, config)
)

// VerifyToken is a middleware to verify a CF Access token
func VerifyToken(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		headers := r.Header

		// Make sure that the incoming request has our token header
		// Could also look in the cookies for CF_AUTHORIZATION
		accessJWT := headers.Get("Cf-Access-Jwt-Assertion")
		if accessJWT == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("No token on the request"))
			return
		}

		// Verify the access token
		ctx := r.Context()
		token, err := verifier.Verify(ctx, accessJWT)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("Invalid token: %s", err.Error())))
			return
		}

		// Extract custom claims
		var claims struct {
			Email string `json:"email"`
			Type  string `json:"type"`
		}

		if err := token.Claims(&claims); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("Invalid claims in token: %s", err.Error())))
		}

		// set the authentication forward header before proxying the request
		r.Header.Add(forwardHeader, claims.Email)
		log.Printf("Authenticated as: %s", claims.Email)

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func main() {
	director := func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", "cloudflare-access-proxy")
		req.URL.Scheme = "http"

		if len(strings.TrimSpace(forwardHost)) > 0 {
			req.URL.Host = forwardHost
		}
	}

	proxy := &httputil.ReverseProxy{Director: director}
	http.Handle("/", VerifyToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})))

	log.Printf("Listening on http://%s/", listenAddr)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("Unable to start server on [%s], error: %s", listenAddr, err.Error())
	}
}
