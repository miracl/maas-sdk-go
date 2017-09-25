package maas

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
)

type testOAC struct {
	// AuthCodeURL
	State      string
	AccessType string
	Prompt     string
	URL        string
	// RequestToken
	GrantType string
	Value     string
	Result    oauth2.TokenResponse
	// All
	Err error
}

func (oac *testOAC) AuthCodeURL(state, accessType, prompt string) (url string) {
	oac.State = state
	oac.AccessType = accessType
	oac.Prompt = prompt
	return oac.URL
}

func (oac *testOAC) RequestToken(grantType, value string) (result oauth2.TokenResponse, err error) {
	oac.GrantType = grantType
	oac.Value = value
	return oac.Result, oac.Err
}

type testOIDC struct {
	// VerifyJWT
	IDToken jose.JWT
	Err     error
}

func (oidc *testOIDC) VerifyJWT(tkn jose.JWT) error {
	oidc.IDToken = tkn
	return oidc.Err
}

type testDoer struct {
	Request  *http.Request
	Response *http.Response
	Error    error
}

func (d *testDoer) Do(rq *http.Request) (*http.Response, error) {
	d.Request = rq
	return d.Response, d.Error
}

func TestGetAuthRequestURL(t *testing.T) {
	oac := &testOAC{
		URL: "test-url",
		Err: nil,
	}

	u, err := getAuthRequestURL("test-state", oac)

	if err != oac.Err {
		t.Error(err)
	}

	if u != oac.URL {
		t.Error("Different URL returned")
	}
	if oac.State != "test-state" {
		t.Error("State not passed")
	}
	if oac.AccessType != "" {
		t.Error("Unexpected access type passed")
	}
	if oac.Prompt != "" {
		t.Error("Unexpected prompt passed")
	}

}

func TestValidateAuth(t *testing.T) {

	oac := &testOAC{
		Result: oauth2.TokenResponse{
			AccessToken: "test-ac",
			TokenType:   "",
			Expires:     0,
			IDToken:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwibmFtZSI6IkpvaG4gRG9lIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUubmV0In0.hmNIOiBOFd5rw6VtROpMnd--57Msm3a3LJkRxUqGzrQ",
			// {
			//   "alg": "HS256",
			//   "typ": "JWT"
			// }
			// {
			//   "sub": "test",
			//   "name": "John Doe",
			//   "email": "test@example.net"
			// }
			RawBody: []byte{},
		},
	}

	oidc := &testOIDC{}

	ac, tkn, err := validateAuth("test-code", oidc, oac)

	if ac != oac.Result.AccessToken {
		t.Error("Wrong access token")
	}
	if tkn.Encode() != oac.Result.IDToken {
		t.Error("Wrong JWT token")
	}
	if err != nil {
		t.Error(err)
	}

}

func TestGetUserInfo(t *testing.T) {

	testUI := UserInfo{
		UserID: "test",
		Email:  "test@example.net",
	}

	body, _ := json.Marshal(testUI)

	d := &testDoer{
		Response: &http.Response{
			Body: ioutil.NopCloser(bytes.NewBuffer(body)),
		},
	}

	ui, err := getUserInfo("test-endpoint", "test-access-token", d)

	if d.Request.Method != "GET" {
		t.Error("Wrong HTTP method sent")
	}
	if d.Request.URL.String() != "test-endpoint" {
		t.Error("Wrong endpoint used")
	}
	if d.Request.Header.Get("Authorization") != "Bearer test-access-token" {
		t.Error("Wrong authorization header sent")
	}

	if err != d.Error {
		t.Error("Unexpected error returned")
	}
	if ui != testUI {
		t.Error("Wrong user info returned")
	}

	t.Logf("%+v", d.Request)

}
