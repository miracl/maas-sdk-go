package dvs

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miracl/maas-sdk-go/pkg/mfa"
)

var (
	ts *httptest.Server

	clientID     = "MockClient"
	clientSecret = "MockSecret"

	validDVSSignature = VerifyRequestSignature{
		Hash:      "15760473979d2027bebca22d4e0ae40f49d0756dda507de71df99bf04d2a7d07",
		MPinID:    "7b226973737565644174223a313439373335363536352c22757365724944223a2273616d75656c652e616e6472656f6c69406578616d706c652e636f6d222c22634944223a22222c226d6f62696c65223a312c2273616c74223a223236343330323663373430363162363162616465643836313262373530626334222c2276223a317d",
		PublicKey: "0f9b60020f2a6108c052ba5d2ac0b24b8b7975ae2a2082ddb5d51b236662620e0c05f8310abe5fbda9ed80d638887ed2859f22b9c902bf88bd52dd083ce26e93144e03e61ad2e14722d29e21fde4eaa9f33f793db7da5e3f6211a7d99a8186e023c7fc60de7185a5d73d11b393530d0245256f7ecc0b1c7c96513b1c717a9b1b",
		U:         "041c9e2ae817f033140a2085add0594643ca44381dae76e0241cbf790371a7f3c406b31ba86b3cd0d744f0a2e87dbcc32d19416d15aaae91f9122cb4d12cb78f07",
		V:         "040ef9b951522009900127820a9a956486b9e11ad05e18e4e86931460d310a2ecf106c9935dc0775a41892577b2f96f87c556dbe87f8fcf7fda546ec21752beada",
	}
)

func TestVerifySignature(t *testing.T) {

	t.Run("ValidSignature", func(t *testing.T) {
		verifyFunc := func(w http.ResponseWriter, r *http.Request) {
			cert := `{
				"certificate":"eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.eyJjQXQiOjE0OTc0NDQ0NTEsImV4cCI6MTQ5NzQ0NDQ2MSwiaGFzaCI6IjE1NzYwNDczOTc5ZDIwMjdiZWJjYTIyZDRlMGFlNDBmNDlkMDc1NmRkYTUwN2RlNzFkZjk5YmYwNGQyYTdkMDcifQ.A19LAJpEZjFhwor0bj02AGh9Nu_VGtyNXeJhqSe1uWc16kJA3Mi7Oe5ocFRUbb5xRuQ8TkzL9kjjiE3CgHLFftCDswHQqLX6nIH6oamVd0lt3fbgAu3pJBtK9U2BKSxwT7q-pQNFuPJTs-3P8XAwegJAbUouHUKuKL1zJTnDmQk"
			}`

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(cert))
		}

		ctx := context.Background()
		dvsClient, err := getDVSClient(ctx, verifyFunc)
		if err != nil {
			t.Error(err)
		}

		dvsReq := &VerifyRequest{
			Signature: validDVSSignature,
			Timestamp: 0,
			Type:      "verification",
		}

		want := ValidSignature
		got, err := dvsClient.VerifySignature(ctx, dvsReq)
		if err != nil {
			t.Error(err)
		}

		if got != want {
			t.Errorf("Got %v; want %v", got, want)
		}
	})

	validationFailedTestCases := []struct {
		respStatus int
		want       VerificationResult
	}{
		{http.StatusUnauthorized, BadPin},
		{http.StatusGone, UserBlocked},
		{http.StatusForbidden, MissingSignature},
	}

	for _, tc := range validationFailedTestCases {
		t.Run(fmt.Sprintf("ValidationFailed %d %s", tc.respStatus, http.StatusText(tc.respStatus)), func(t *testing.T) {
			verifyFunc := func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.respStatus)
			}

			ctx := context.Background()
			dvsClient, err := getDVSClient(ctx, verifyFunc)
			if err != nil {
				t.Error(err)
			}

			dvsReq := &VerifyRequest{
				Signature: validDVSSignature,
				Timestamp: 0,
				Type:      "verification",
			}

			want := tc.want
			got, err := dvsClient.VerifySignature(ctx, dvsReq)

			if got != want {
				t.Errorf("Got %v; want %v", got, want)
			}
		})
	}

	invalidRespTestCases := []struct {
		respBody string
		want     string
	}{
		{`{"no-certificate":"ey.fQ.nD"}`, "no `certificate` in the JSON response"},
		{`{"certificate":"ey.fQ"}`, "malformed jwt"},
		{`{"certificate":"eyfQnD"}`, "malformed jwt"},
		{`"invalid":"json"}`, "invalid character"},
	}

	for _, tc := range invalidRespTestCases {
		t.Run("InvalidResponse", func(t *testing.T) {
			verifyFunc := func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(tc.respBody))
			}

			ctx := context.Background()
			dvsClient, err := getDVSClient(ctx, verifyFunc)
			if err != nil {
				t.Error(err)
			}

			dvsReq := &VerifyRequest{
				Signature: validDVSSignature,
				Timestamp: 0,
				Type:      "verification",
			}

			got, err := dvsClient.VerifySignature(ctx, dvsReq)
			if got != InvalidSignature {
				t.Errorf("Got %v; want %v", got, InvalidSignature)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Error(err)
			}
		})
	}

	t.Run("RequestAndResponseHashesDiffer", func(t *testing.T) {
		verifyFunc := func(w http.ResponseWriter, r *http.Request) {
			cert := `{
				"certificate":"eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.eyJjQXQiOjE0OTc0NDQ0NTEsImV4cCI6MTQ5NzQ0NDQ2MSwiaGFzaCI6IjE1NzYwNDczOTc5ZDIwMjdiZWJjYTIyZDRlMGFlNDBmNDlkMDc1NmRkYTUwN2RlNzFkZjk5YmYwNGQyYTdkMDcifQ.A19LAJpEZjFhwor0bj02AGh9Nu_VGtyNXeJhqSe1uWc16kJA3Mi7Oe5ocFRUbb5xRuQ8TkzL9kjjiE3CgHLFftCDswHQqLX6nIH6oamVd0lt3fbgAu3pJBtK9U2BKSxwT7q-pQNFuPJTs-3P8XAwegJAbUouHUKuKL1zJTnDmQk"
			}`

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(cert))
		}

		ctx := context.Background()
		dvsClient, err := getDVSClient(ctx, verifyFunc)
		if err != nil {
			t.Error(err)
		}

		dvsReq := &VerifyRequest{
			Signature: VerifyRequestSignature{
				Hash:      "different-hash-value",
				MPinID:    "7b226973737565644174223a313439373335363536352c22757365724944223a2273616d75656c652e616e6472656f6c69406578616d706c652e636f6d222c22634944223a22222c226d6f62696c65223a312c2273616c74223a223236343330323663373430363162363162616465643836313262373530626334222c2276223a317d",
				PublicKey: "0f9b60020f2a6108c052ba5d2ac0b24b8b7975ae2a2082ddb5d51b236662620e0c05f8310abe5fbda9ed80d638887ed2859f22b9c902bf88bd52dd083ce26e93144e03e61ad2e14722d29e21fde4eaa9f33f793db7da5e3f6211a7d99a8186e023c7fc60de7185a5d73d11b393530d0245256f7ecc0b1c7c96513b1c717a9b1b",
				U:         "041c9e2ae817f033140a2085add0594643ca44381dae76e0241cbf790371a7f3c406b31ba86b3cd0d744f0a2e87dbcc32d19416d15aaae91f9122cb4d12cb78f07",
				V:         "040ef9b951522009900127820a9a956486b9e11ad05e18e4e86931460d310a2ecf106c9935dc0775a41892577b2f96f87c556dbe87f8fcf7fda546ec21752beada",
			},
			Timestamp: 0,
			Type:      "verification",
		}

		got, err := dvsClient.VerifySignature(ctx, dvsReq)
		if got != InvalidSignature {
			t.Errorf("Got %v; want %v", got, InvalidSignature)
		}

		if !strings.Contains(err.Error(), "signature hash and response hash do not match") {
			t.Error(err)
		}
	})

	t.Run("RequestTimestampAfterResponseTimestamp", func(t *testing.T) {
		verifyFunc := func(w http.ResponseWriter, r *http.Request) {
			cert := `{
				"certificate":"eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.eyJjQXQiOjE0OTc0NDQ0NTEsImV4cCI6MTQ5NzQ0NDQ2MSwiaGFzaCI6IjE1NzYwNDczOTc5ZDIwMjdiZWJjYTIyZDRlMGFlNDBmNDlkMDc1NmRkYTUwN2RlNzFkZjk5YmYwNGQyYTdkMDcifQ.A19LAJpEZjFhwor0bj02AGh9Nu_VGtyNXeJhqSe1uWc16kJA3Mi7Oe5ocFRUbb5xRuQ8TkzL9kjjiE3CgHLFftCDswHQqLX6nIH6oamVd0lt3fbgAu3pJBtK9U2BKSxwT7q-pQNFuPJTs-3P8XAwegJAbUouHUKuKL1zJTnDmQk"
			}`

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(cert))
		}

		ctx := context.Background()
		dvsClient, err := getDVSClient(ctx, verifyFunc)
		if err != nil {
			t.Error(err)
		}

		dvsReq := &VerifyRequest{
			Signature: validDVSSignature,
			Timestamp: math.MaxInt32,
			Type:      "verification",
		}

		got, err := dvsClient.VerifySignature(ctx, dvsReq)
		if got != InvalidSignature {
			t.Errorf("Got %v; want %v", got, InvalidSignature)
		}

		if !strings.Contains(err.Error(), "the transaction is signed before the issue time") {
			t.Error(err)
		}
	})

	t.Run("InvalidResponsePayload", func(t *testing.T) {
		verifyFunc := func(w http.ResponseWriter, r *http.Request) {
			cert := `{
				"certificate":"eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.invalid_payload.A19LAJpEZjFhwor0bj02AGh9Nu_VGtyNXeJhqSe1uWc16kJA3Mi7Oe5ocFRUbb5xRuQ8TkzL9kjjiE3CgHLFftCDswHQqLX6nIH6oamVd0lt3fbgAu3pJBtK9U2BKSxwT7q-pQNFuPJTs-3P8XAwegJAbUouHUKuKL1zJTnDmQk"
			}`

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(cert))
		}

		ctx := context.Background()
		dvsClient, err := getDVSClient(ctx, verifyFunc)
		if err != nil {
			t.Error(err)
		}

		dvsReq := &VerifyRequest{
			Signature: validDVSSignature,
			Timestamp: 0,
			Type:      "verification",
		}

		got, err := dvsClient.VerifySignature(ctx, dvsReq)
		if got != InvalidSignature {
			t.Errorf("Got %v; want %v", got, InvalidSignature)
		}
	})
}

func TestCreateDocumentHash(t *testing.T) {
	document := "sample document"
	want := "1789c9eeee7dcbf9a5e9b47374e244f85263dc45922a249d37f7ba9fd4efb850"
	client := Client{}

	got := client.CreateDocumentHash(document)
	if got != want {
		t.Errorf("Got %v; want %v", got, want)
	}
}

func TestCreateAuthToken(t *testing.T) {
	docHash := "1789c9eeee7dcbf9a5e9b47374e244f85263dc45922a249d37f7ba9fd4efb850"
	clientID := "MockClientId"
	clientSecret := "MockClientSecret"
	ctx := context.Background()

	mfaClient, err := mfa.New(ctx, clientID, clientSecret, "")
	if err != nil {
		t.Error(err)
	}

	dvsClient := New(ctx, mfaClient)

	want := "TW9ja0NsaWVudElkOmU1M2U4ZTY2NGM0NWJlMzQyZWZjZmExNDZlNTM4ODc3ZGYyYWQ2NDViNGExYTA1OWIxNmY5NTBkMzhhZGUzYzU="

	got, err := dvsClient.CreateAuthToken(docHash)
	if err != nil {
		t.Error(err)
	}

	if got != want {
		t.Errorf("Got %v; want %v", got, want)
	}
}

func getDVSClient(ctx context.Context, verifyFunc http.HandlerFunc) (*Client, error) {
	mux := defaultTestMux()
	mux.HandleFunc("/dvs/verify", http.HandlerFunc(verifyFunc))

	if ts != nil {
		ts.Close()
	}

	l, err := net.Listen("tcp", "127.0.0.1:12345")
	if err != nil {
		return nil, err
	}

	ts = httptest.NewUnstartedServer(mux)
	ts.Listener.Close()
	ts.Listener = l
	ts.Start()

	mfaClient, err := mfa.New(ctx, clientID, clientSecret, "", mfa.WithDiscoveryURL(ts.URL))
	if err != nil {
		return nil, err
	}

	return New(ctx, mfaClient), nil
}

func defaultTestMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		discoveryConfig := `{
			"subject_types_supported": [ "public" ],
			"userinfo_signing_alg_values_supported": [ "RS256", "RS384", "RS512" ],
			"claims_supported": [ "sub", "iss", "email", "email_verified" ],
			"issuer": "http://127.0.0.1:12345",
			"response_types_supported": [ "code", "id_token", "id_token token", "code id_token", "code id_token token" ],
			"token_endpoint": "127.0.0.1:12345/oidc/token",
			"jwks_uri": "127.0.0.1:12345/oidc/certs",
			"scopes_supported": [ "openid", "profile", "email" ],
			"token_endpoint_auth_methods_supported": [ "client_secret_post", "client_secret_basic" ],
			"id_token_signing_alg_values_supported": [ "RS256", "RS384", "RS512" ],
			"userinfo_endpoint": "127.0.0.1:12345/oidc/userinfo",
			"authorization_endpoint": "127.0.0.1:12345/authorize"
		  }`

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(discoveryConfig))
	}))

	mux.HandleFunc("/oidc/certs", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oidcJWKs := `{
			"keys": [
			  {
				"kty": "RSA",
				"use": "sig",
				"kid": "31-07-2016",
				"n": "kwBfKdZTTt8dD-o1VPXKCH4hi28-KUMsPy7OYBrk4lgCd1EHZCVvZdKkcjPW0kGjC3vuee7C5v516Siids684n_V8mznvLwNFGKJ3fdiubkxKc5cpgPrxH86uHr0sU-ACoWhkW3KjFKBb-WNYSqcNxKaXI-dcKJtAaZNqnbwjf0_fkWAEsrPYyMPeYt6AjX2vDhqu4a4zrclKiy2ngEkZ91GwrvATX5UrooefIuNc2PRC-Y7mccvcm9cK0V6xLeWovivWX-GTHwMuPymIJGyDqo-6NRkqv6sl-QIFEzohQd3jSLUyt71u8lqgOlfW2JN7T_HOOkg_ibq6u-k94HJQw",
				"e": "AQAB"
			  }
			]
		  }`

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(oidcJWKs))
	}))

	mux.HandleFunc("/dvs/jwks", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dvsJWKs := `{
			"keys": [
				{
					"kty": "RSA",
					"use":"sig",
					"kid":"s1",
					"n":"kWp2zRA23Z3vTL4uoe8kTFptxBVFunIoP4t_8TDYJrOb7D1iZNDXVeEsYKp6ppmrTZDAgd-cNOTKLd4M39WJc5FN0maTAVKJc7NxklDeKc4dMe1BGvTZNG4MpWBo-taKULlYUu0ltYJuLzOjIrTHfarucrGoRWqM0sl3z2-fv9k",
					"e":"AQAB"
				}
			]
		}`

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(dvsJWKs))
	}))

	return mux
}
