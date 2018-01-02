package maas

import (
	"flag"
	"net/http"
	"testing"
)

var (
	integration  = flag.Bool("integration", false, "run integration tests")
	testEndpoint = flag.String("test-endpoint", "http://localhost:8002", "integration test endpoint")
)

func TestMain(m *testing.M) {
	flag.Parse()
	m.Run()
}

func TestProxyConnection(t *testing.T) {
	if !*integration {
		t.Skip()
	}

	req, err := http.NewRequest("GET", *testEndpoint, nil)
	if err != nil {
		t.Error(err)
	}

	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Error(resp.Status)
	}
}
