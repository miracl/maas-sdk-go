package maas

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/coreos/go-oidc/oidc"
	"github.com/jonboulle/clockwork"
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

type testProviderConfigGetter struct {
	IssuerURL         string
	IsFetchSuccessful bool
	Error             error
}

func (tp *testProviderConfigGetter) Get() (oidc.ProviderConfig, error) {
	if !tp.IsFetchSuccessful {
		tp.IsFetchSuccessful = true
		return oidc.ProviderConfig{}, tp.Error
	}

	issuer, err := url.Parse(tp.IssuerURL)
	if err != nil {
		return oidc.ProviderConfig{}, err
	}

	provider := oidc.ProviderConfig{Issuer: issuer}

	return provider, nil
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

func TestPopulateDefaultConfig(t *testing.T) {
	var cfg Config
	cfg = populateDefaultConfig(cfg)

	if cfg.HTTPClient != http.DefaultClient {
		t.Errorf("Wrong Http client: expected %v, got %v", http.DefaultClient, cfg.HTTPClient)
	}

	expectedClock := clockwork.NewRealClock()
	if cfg.Clock != expectedClock {
		t.Errorf("Wrong Clock: expected %v, got %v", expectedClock, cfg.Clock)
	}

	expectedScope := []string{"openid", "email", "sub"}
	if !reflect.DeepEqual(cfg.Scope, expectedScope) {
		t.Errorf("Wrong Scope: expected %v, got %v", expectedScope, cfg.Scope)
	}

	expectedDiscoveryURI := DiscoveryURI
	if cfg.DiscoveryURI != expectedDiscoveryURI {
		t.Errorf("Wrong DiscoveryURI: expected %v, got %v", expectedDiscoveryURI, cfg.DiscoveryURI)
	}
}

func TestGetProviderConfig(t *testing.T) {
	mcfg := Config{
		DiscoveryURI:    "test-url",
		Clock:           clockwork.NewRealClock(),
		ProviderRetries: 5,
		RetryPeriod:     10 * time.Millisecond,
	}

	tpcg := testProviderConfigGetter{IssuerURL: mcfg.DiscoveryURI, Error: errors.New("failed to fetch provider config")}
	provider, err := getProviderConfig(mcfg, &tpcg)
	if err != nil {
		t.Error(err)
	}

	expectedURL := "test-url"
	if provider.Issuer.String() != expectedURL {
		t.Errorf("Wrong ProviderConfig issuer: expected %v, got %v", expectedURL, provider.Issuer)
	}

	tpcg.IsFetchSuccessful = false
	mcfg.ProviderRetries = 0
	_, err = getProviderConfig(mcfg, &tpcg)
	if err != tpcg.Error {
		t.Error("Unexpected error returned")
	}
}

func TestNewClient(t *testing.T) {
	hc := &testDiscoveryDoer{}

	_, err := NewClient(Config{
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		RedirectURI:  "test.com",
		DiscoveryURI: "http://test-discovery.com",
		HTTPClient:   hc,
	})

	if err != nil {
		t.Error(err)
	}
}

type testDiscoveryDoer struct {
	Request  *http.Request
	Response *http.Response
	Error    error
}

func (d *testDiscoveryDoer) Do(rq *http.Request) (*http.Response, error) {
	d.Request = rq

	jsonString := `{"subject_types_supported":["public"],"userinfo_signing_alg_values_supported":["RS256","RS384","RS512"],"claims_supported":["sub","iss","email","email_verified"],"issuer":"http://test-discovery.com","response_types_supported":["code","id_token","id_token token","code id_token","code id_token token"],"token_endpoint":"http://test-discovery.com/oidc/token","jwks_uri":"http://test-discovery.com/oidc/certs","scopes_supported":["openid","profile","email"],"token_endpoint_auth_methods_supported":["client_secret_post","client_secret_basic"],"id_token_signing_alg_values_supported":["RS384","RS512","RS256"],"userinfo_endpoint":"http://test-discovery.com/oidc/userinfo","authorization_endpoint":"http://test-discovery.com/authorize"}`
	pcfg := oidc.ProviderConfig{}
	pcfg.UnmarshalJSON([]byte(jsonString))
	body, _ := pcfg.MarshalJSON()

	d.Response = &http.Response{
		Body: ioutil.NopCloser(bytes.NewBuffer(body)),
	}

	return d.Response, d.Error
}
