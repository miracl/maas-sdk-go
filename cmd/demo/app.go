package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/miracl/maas-sdk-go/pkg/dvs"
	"github.com/miracl/maas-sdk-go/pkg/mfa"
	"golang.org/x/oauth2"
)

type example struct {
	html           *template.Template
	stateGenerator func() string
	stateStorage   set
	mfa            *mfa.Client
	dvs            *dvs.Client
}

func new(f *flags) (*example, error) {
	var err error

	e := &example{
		stateGenerator: func() string { return strconv.Itoa(rand.Intn(999999)) },
		stateStorage:   newSet(),
	}

	// create the mfa client
	e.mfa, err = mfa.New(
		context.Background(),
		f.clientID, f.clientSecret, f.redirectURL,
		mfa.WithDiscoveryURL(f.issuer),
	)
	if err != nil {
		return nil, err
	}

	e.dvs = dvs.New(context.Background(), e.mfa)

	// parse the template
	e.html, err = template.ParseFiles(
		fmt.Sprintf("%v/index.tmpl", f.templatesDir),
	)
	if err != nil {
		return nil, err
	}

	return e, nil
}

func (e *example) index(w http.ResponseWriter, r *http.Request) {
	state := e.stateGenerator()
	e.stateStorage.add(state)
	e.html.Execute(w, map[string]string{
		"AuthURL": e.mfa.OAuthConfig.AuthCodeURL(state),
	})
}

func (e *example) login(w http.ResponseWriter, r *http.Request) {
	// Validate the state
	state := r.URL.Query().Get("state")
	if !e.stateStorage.contains(state) {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}
	e.stateStorage.pop(state)

	// Exchange and verify token.
	oauth2Token, err := e.mfa.Verify(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// get user data
	userInfo, err := e.mfa.Provider.UserInfo(r.Context(), oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
		return
	}

	userInfoJSON, err := json.MarshalIndent(userInfo, "", "	")
	if err != nil {
		http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
		return
	}
	e.html.Execute(w, map[string]string{
		"UserInfo": string(userInfoJSON),
	})
}

func (e *example) config(w http.ResponseWriter, r *http.Request) {
	state := e.stateGenerator()
	e.stateStorage.add(state)

	config := struct {
		ClientID    string `json:"clientID"`
		RedirectURL string `json:"redirectURL"`
		State       string `json:"state"`
	}{
		e.mfa.OAuthConfig.ClientID,
		e.mfa.OAuthConfig.RedirectURL,
		state,
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(configJSON)
}

func (e *example) verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	signature, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
	}

	dvsReq := &dvs.VerifyRequest{}
	if err := json.Unmarshal(signature, dvsReq); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	verificationResult, err := e.dvs.VerifySignature(r.Context(), dvsReq)

	verifyRes := struct {
		Valid  bool   `json:"valid"`
		Status string `json:"status"`
	}{
		err == nil,
		verificationResult.String(),
	}

	verifyResJSON, err := json.Marshal(verifyRes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(verifyResJSON))
}

func (e *example) hash(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	doc, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
	}

	docHash := e.dvs.CreateDocumentHash(string(doc))

	hashRes := struct {
		Hash      string `json:"hash"`
		Timestamp int    `json:"timestamp"`
	}{
		docHash,
		int(time.Now().Unix()),
	}

	hashResJSON, err := json.Marshal(hashRes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(hashResJSON))
}
