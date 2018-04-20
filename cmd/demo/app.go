package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"strconv"

	"github.com/miracl/maas-sdk-go/pkg/mfa"
	"golang.org/x/oauth2"
)

type example struct {
	html           *template.Template
	stateGenerator func() string
	stateStorage   set
	mfa            *mfa.Client
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

	configJSON, err := json.MarshalIndent(config, "", "	")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(configJSON)
}
