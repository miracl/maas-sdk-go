package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/miracl/maas-sdk-go"
)

const (
	serviceName = "rpa-example"
	serviceID   = "rpa-example"
	state       = "test-state"
	seesionKey  = "session-key"
)

var (
	clientID     = flag.String("client-id", "", "OIDC Client Id")
	clientSecret = flag.String("client-secret", "", "OIDC Client Secret")
	redirectURL  = flag.String("redirect", "", "Redirect URL")
	addr         = flag.String("addr", ":8002", "Listen address")
	templatesDir = flag.String("templates-dir", "templates", "Template files location")
	debug        = flag.Bool("debug", false, "Debug mode")

	backend = flag.String("backend", maas.DiscoveryURI, "Backend url")

	mc maas.Client
)

// Below there is an exemplary implementation of server side session.
// It is overly simplistic for the purposes of the example, as the main point
// is the usage of the SDK.
// Real applications could / should implement session in more advanced manner
// or use whatever is provided from the framework they use.

// CheckSession verifies that the request provides a valid session.
func checkSession(r *http.Request, sessions map[string]maas.UserInfo) (user maas.UserInfo, err error) {
	c, err := r.Cookie("session")
	if err != nil {
		return user, err
	}
	user, ok := sessions[c.Value]
	if !ok {
		return maas.UserInfo{}, fmt.Errorf("Session %v does not exist", c.Value)
	}
	return user, err
}

// CreateSession creates a new valid session
func createSession(w http.ResponseWriter, user maas.UserInfo, sessions map[string]maas.UserInfo) {
	sessionID := time.Now().Format(time.RFC850)
	sessions[sessionID] = user
	expiration := time.Now().Add(24 * time.Hour)
	cookie := http.Cookie{Name: "session", Value: sessionID, Expires: expiration}
	http.SetCookie(w, &cookie)
}

// DeleteSession removes (invalidates) session
func deleteSession(r *http.Request, w http.ResponseWriter, sessions map[string]maas.UserInfo) {
	c, _ := r.Cookie("session")
	delete(sessions, c.Value)
	c.Value = ""
	c.Expires = time.Time{}
	http.SetCookie(w, c)
}

// Flash is a one time message to be displayed
type flash struct {
	Category string
	Message  string
}

// Application context in request
type context struct {
	Messages   []flash
	Retry      bool
	AuthURL    string
	Authorized bool
	Email      string
	UserID     string
}

func main() {
	// Parse command line options
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.LUTC)
	flag.Parse()

	if *clientID == "" {
		log.Fatal("client-id required")
	}
	if *clientSecret == "" {
		log.Fatal("client-secret required")
	}
	if *redirectURL == "" {
		log.Fatal("Redirect URL required")
	}

	mc, err := maas.NewClient(maas.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		RedirectURI:  *redirectURL,
		DiscoveryURI: *backend,
	})
	if err != nil {
		log.Fatal(err)
	}

	sessions := map[string]maas.UserInfo{}

	http.HandleFunc("/oidc", func(w http.ResponseWriter, r *http.Request) {
		ctx := context{}
		ctx.Messages = make([]flash, 10)

		code := r.URL.Query().Get("code")
		// CExchange authorization code for access token
		accessToken, jwt, err := mc.ValidateAuth(code)
		if err != nil {
			// if authorization code is invalid, offer the user to login
			// mpad needs authURL
			authURL, e := mc.GetAuthRequestURL("test-state")
			if e != nil {
				ctx.Messages = append(ctx.Messages, flash{Category: "error", Message: e.Error()})
			}
			ctx.AuthURL = authURL
		}
		if *debug {
			claims, _ := jwt.Claims()
			log.Printf("Access token: %v", accessToken)
			log.Printf("JTW payload: %+v", claims)
		}

		// Retrieve use info from oidc server
		user, err := mc.GetUserUnfo(accessToken)
		if err != nil {
			ctx.Messages = append(ctx.Messages, flash{Category: "error", Message: err.Error()})
		} else {
			// If user info is successfully retrieved, create session and
			// redirect to `protected` page
			createSession(w, user, sessions)
			http.Redirect(w, r, "/", 302)
			return
		}

		// Else show the login page, along with any error messages
		if t, err := template.New("index.tmpl").ParseFiles(filepath.Join(*templatesDir, "index.tmpl")); err != nil {
			log.Fatalf("Failed to parse template: %+v", err)
		} else {
			t.Execute(w, ctx)
		}
	})
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		// On logout delete session and redirect to index
		deleteSession(r, w, sessions)
		http.Redirect(w, r, "/", 302)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		ctx := context{}
		ctx.Messages = make([]flash, 0)

		if user, err := checkSession(r, sessions); err != nil {
			// If user is not logged, populate authURL for mpad
			// so the user can authenticate
			authURL, e := mc.GetAuthRequestURL("test-state")
			if e != nil {
				ctx.Messages = append(ctx.Messages, flash{Category: "error", Message: e.Error()})
			}
			ctx.AuthURL = authURL
		} else {
			// Else display info for logged user (this is `protected` page)
			ctx.Authorized = true
			ctx.UserID = user.UserID
			ctx.Email = user.Email
		}

		if t, err := template.New("index.tmpl").ParseFiles(filepath.Join(*templatesDir, "index.tmpl")); err != nil {
			log.Fatalf("Failed to parse template: %+v", err)
		} else {
			if err = t.Execute(w, ctx); err != nil {
				log.Println(err)
			}
		}
	})

	log.Printf("Service %s started. Listening on %s", serviceName, *addr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatal(err)
	}
}
