package maas

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	phttp "github.com/coreos/go-oidc/http"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/coreos/go-oidc/oidc"
	"github.com/jonboulle/clockwork"
)

const (
	// DiscoveryURI is the discovery URL of the Miracl OIDC server
	DiscoveryURI = "https://api.mpin.io"
)

// Config is configuration struct for initializing a Client object with NewClient.
type Config struct {
	ClientID        string          // RP client ID at authorization server (`client_id` in OIDC 1.0). Required.
	ClientSecret    string          // RP client secret at authorization server (`client_secret` in OIDC 1.0). Required.
	RedirectURI     string          // URI for back redirection from authorization server to RP (`redirect_uri` in OIDC 1.0). Required.
	DiscoveryURI    string          // DiscoveryURI is the discovery URL of the Miracl OIDC server, without the `.well-known/openid-configuration`
	HTTPClient      phttp.Client    // HTTP client to use for requests to authorization server. If left out, `http.DefaultClient` will be used
	ProviderRetries int             // Number of retries to make while fetching provider configuration from discovery URI.
	RetryPeriod     time.Duration   // Wait period between retries.
	Clock           clockwork.Clock // A clock object. If left out, real clock will be used. Fake clock can be passed for testing.
	Scope           []string        // Scope of the claim (`scope` in OIDC 1.0). If not set, functional default will be populated.
}

// client is a local implementation of `Client` interface.
type client struct {
	oidc     oidcClient
	oauth    oauthClient
	provider oidc.ProviderConfig
	config   Config
}

// Client is the public interface for communicating with MAAS authorization server.
type Client interface {
	GetAuthRequestURL(state string) (u string, err error)
	ValidateAuth(code string) (string, jose.JWT, error)
	GetUserInfo(accessToken string) (ui UserInfo, err error)
}

// UserInfo holds user information retrieved from UserInfo endpoint.
type UserInfo struct {
	UserID string `json:"sub"`
	Email  string `json:"email"`
}

// oauthClient is a local interface used to abstract oauth2.Client capabilities for testing.
type oauthClient interface {
	AuthCodeURL(state, accessType, prompt string) (url string)
	RequestToken(grantType, value string) (result oauth2.TokenResponse, err error)
}

// oidcClient is a local interface used to abstract oidc.Client capabilities for testing.
type oidcClient interface {
	VerifyJWT(jose.JWT) error
}

// httpDoer is a local interface used to abstract http.Client capabilities for testing.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// providerConfigGetter is a local implementation of `oidc.ProviderConfigGetter` interface.
type providerConfigGetter struct {
	HTTPClient phttp.Client
	IssuerURL  string
}

func (p providerConfigGetter) Get() (oidc.ProviderConfig, error) {
	return oidc.FetchProviderConfig(p.HTTPClient, p.IssuerURL)
}

func populateDefaultConfig(cfg Config) Config {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.Clock == nil {
		cfg.Clock = clockwork.NewRealClock()
	}
	if cfg.Scope == nil {
		cfg.Scope = []string{"openid", "email", "sub"}
	}
	if cfg.DiscoveryURI == "" {
		cfg.DiscoveryURI = DiscoveryURI
	}
	return cfg
}

func getProviderConfig(mcfg Config, pcg oidc.ProviderConfigGetter) (provider oidc.ProviderConfig, err error) {
	for tries := 0; true; {
		provider, err = pcg.Get()
		if err == nil {
			return provider, nil
		}
		tries++
		if tries > mcfg.ProviderRetries {
			return oidc.ProviderConfig{}, err
		}

		mcfg.Clock.Sleep(mcfg.RetryPeriod)
	}

	return
}

// NewClient instantiates a new `Client` object.
// Normally you need to populate `ClientID`, `ClientSecret`
// and `RedirectURI` fields in `mcfg` argument.
func NewClient(mcfg Config) (mc Client, err error) {
	mcfg = populateDefaultConfig(mcfg)

	pcg := providerConfigGetter{HTTPClient: mcfg.HTTPClient, IssuerURL: mcfg.DiscoveryURI}
	provider, err := getProviderConfig(mcfg, pcg)
	if err != nil {
		return nil, err
	}

	credentials := oidc.ClientCredentials{
		ID:     mcfg.ClientID,
		Secret: mcfg.ClientSecret,
	}

	oidc, err := oidc.NewClient(oidc.ClientConfig{
		Credentials:    credentials,
		RedirectURL:    mcfg.RedirectURI,
		ProviderConfig: provider,
		Scope:          mcfg.Scope,
		HTTPClient:     mcfg.HTTPClient,
	})
	if err != nil {
		return nil, err
	}

	oidc.SyncProviderConfig(mcfg.DiscoveryURI)

	oauth, err := oidc.OAuthClient()
	if err != nil {
		return nil, err
	}

	return &client{
		oidc:     oidc,
		oauth:    oauth,
		provider: provider,
		config:   mcfg,
	}, err
}

// GetAuthRequestURL constructs redirect URL for authorization via M-Pin system.
// Argument `state` is an opaque value set by the RP to maintain state between request and callback.
func (mc *client) GetAuthRequestURL(state string) (string, error) {
	return getAuthRequestURL(state, mc.oauth)
}

func getAuthRequestURL(state string, oac oauthClient) (u string, err error) {

	uo, err := url.Parse(oac.AuthCodeURL(state, "", ""))
	if err != nil {
		return "", err
	}
	u = uo.String()

	return u, err
}

// ValidateAuth exchanges authorization code for access and id tokens if validation succeeds.
// Argument `state` is an opaque value set by the RP to maintain state between request and callback.
// Argument `code` is the authorization code sent back in the redirect from from authorization server.
func (mc *client) ValidateAuth(code string) (string, jose.JWT, error) {
	return validateAuth(code, mc.oidc, mc.oauth)
}

func validateAuth(code string, oidc oidcClient, oac oauthClient) (string, jose.JWT, error) {

	t, err := oac.RequestToken(oauth2.GrantTypeAuthCode, code)
	if err != nil {
		return "", jose.JWT{}, err
	}
	jwt, err := jose.ParseJWT(t.IDToken)
	if err != nil {
		return "", jose.JWT{}, err
	}
	if err = oidc.VerifyJWT(jwt); err != nil {
		return "", jose.JWT{}, err
	}

	return t.AccessToken, jwt, err

}

// GetUserInfo retrieves `UserInfo` from authorization server.
// Argument `accessToken` is the access token to be sent to authorization server.
func (mc *client) GetUserInfo(accessToken string) (ui UserInfo, err error) {
	return getUserInfo(mc.provider.UserInfoEndpoint.String(), accessToken, mc.config.HTTPClient)
}

func getUserInfo(userInfoEndoint, accessToken string, h httpDoer) (ui UserInfo, err error) {

	req, err := http.NewRequest("GET", userInfoEndoint, new(bytes.Buffer))
	if err != nil {
		return ui, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := h.Do(req)
	if err != nil {
		return ui, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if err = json.Unmarshal(body, &ui); err != nil {
		return UserInfo{}, err
	}

	return ui, err
}
