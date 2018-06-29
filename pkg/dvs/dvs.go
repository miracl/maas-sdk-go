package dvs

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	oidc "github.com/coreos/go-oidc"
	"github.com/miracl/maas-sdk-go/pkg/mfa"

	"github.com/pkg/errors"
)

// VerifyRequest is the request payload for the dvs verify request.
type VerifyRequest struct {
	Signature VerifyRequestSignature `json:"signature"`
	Timestamp int                    `json:"timestamp"`
	Type      string                 `json:"type"`
}

// VerifyRequestSignature is the signature part of the dvs verify request.
type VerifyRequestSignature struct {
	Hash      string `json:"hash"`
	MPinID    string `json:"mpinId"`
	PublicKey string `json:"publicKey"`
	U         string `json:"u"`
	V         string `json:"v"`
}

// VerifyResponse is the response from the the dvs verify request.
type VerifyResponse struct {
	Certificate string `json:"certificate"`
}

// VerificationResult is used to notify the user what is the DVS verification status.
type VerificationResult int

// VerificationResult values.
const (
	ValidSignature VerificationResult = iota
	BadPin
	UserBlocked
	MissingSignature
	InvalidSignature
)

var verificationResultText = map[VerificationResult]string{
	ValidSignature:   "valid signature",
	BadPin:           "bad pin",
	UserBlocked:      "user blocked",
	MissingSignature: "missing signature",
	InvalidSignature: "invalid signature",
}

func (r VerificationResult) String() string { return verificationResultText[r] }

// Client is a client used for DVS verification.
type Client struct {
	mfa        *mfa.Client
	httpClient *http.Client
	Keys       oidc.KeySet
}

// New returns new DVS client.
func New(ctx context.Context, mfa *mfa.Client, opts ...func(*Client)) *Client {
	keys := oidc.NewRemoteKeySet(ctx, fmt.Sprintf("%v/dvs/jwks", mfa.Issuer()))
	client := &Client{
		mfa:        mfa,
		Keys:       keys,
		httpClient: http.DefaultClient,
	}

	for _, f := range opts {
		f(client)
	}

	return client
}

// WithHTTPClient is a functional option to set the http client
func WithHTTPClient(httpClient *http.Client) func(*Client) {
	return func(c *Client) { c.httpClient = httpClient }
}

// VerifySignature sends signature for verification to the DVS (designated verifier scheme) service and verifies the received response.
func (c *Client) VerifySignature(ctx context.Context, dvsReq *VerifyRequest) (VerificationResult, error) {
	resp, err := c.verifySignature(ctx, dvsReq)
	if err != nil {
		return InvalidSignature, err
	}

	res, err := c.validateResponse(ctx, dvsReq, resp)
	if err != nil {
		return res, err
	}

	return res, nil
}

// CreateDocumentHash creates a document hash using the SHA256 hashing algorithm.
func (c *Client) CreateDocumentHash(doc string) string {
	docHash := sha256.Sum256([]byte(doc))
	docHashHex := hex.EncodeToString(docHash[:])
	return docHashHex
}

// CreateAuthToken creates auth token for authentication in front of the DVS service.
func (c *Client) CreateAuthToken(docHash string) (string, error) {
	m := hmac.New(sha256.New, []byte(c.mfa.OAuthConfig.ClientSecret))
	if _, err := m.Write([]byte(docHash)); err != nil {
		return "", err
	}

	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", c.mfa.OAuthConfig.ClientID, hex.EncodeToString(m.Sum(nil)))))
	return auth, nil
}

func (c *Client) verifySignature(ctx context.Context, dvsReq *VerifyRequest) (*http.Response, error) {
	auth, err := c.CreateAuthToken(dvsReq.Signature.Hash)
	if err != nil {
		return nil, err
	}

	reqBodyJSON, err := json.Marshal(dvsReq)
	if err != nil {
		return nil, err
	}

	baseAddr, err := url.Parse(c.mfa.Issuer())
	if err != nil {
		return nil, err
	}

	verifyEndpoint, err := url.Parse("/dvs/verify")
	if err != nil {
		return nil, err
	}

	verifyURL := baseAddr.ResolveReference(verifyEndpoint)

	req, err := http.NewRequest("POST", verifyURL.String(), bytes.NewReader(reqBodyJSON))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("MAAS-HMAC-SHA256 %s", auth))

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *Client) validateResponse(ctx context.Context, req *VerifyRequest, resp *http.Response) (VerificationResult, error) {
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return BadPin, errors.Errorf("request failed: %v", resp)
		case http.StatusGone:
			return UserBlocked, errors.Errorf("request failed: %v", resp)
		default:
			return MissingSignature, errors.Errorf("request failed: %v", resp)
		}
	}

	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return InvalidSignature, err
	}

	respBody := &VerifyResponse{}
	if err := json.Unmarshal(raw, respBody); err != nil {
		return InvalidSignature, err
	}

	if respBody.Certificate == "" {
		return InvalidSignature, errors.New("no `certificate` in the JSON response")
	}

	rawPayload, err := c.Keys.VerifySignature(ctx, respBody.Certificate)
	if err != nil {
		return InvalidSignature, err
	}

	payload := struct {
		CreatedAt int    `json:"cAt"`
		Exp       int    `json:"exp"`
		Hash      string `json:"hash"`
	}{}

	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return InvalidSignature, err
	}

	if req.Signature.Hash != payload.Hash {
		return InvalidSignature, errors.New("signature hash and response hash do not match")
	}

	if req.Timestamp > payload.CreatedAt {
		return InvalidSignature, errors.New("the transaction is signed before the issue time")
	}

	return ValidSignature, nil
}
