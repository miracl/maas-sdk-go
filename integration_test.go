// +build integration

package maas

import (
	"net/http"
	"testing"
)

func TestProxyConnection(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:8002", nil)
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
