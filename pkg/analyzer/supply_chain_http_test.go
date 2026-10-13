package analyzer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOSVEndpointConfiguration(t *testing.T) {
	t.Setenv("TOOLTRUST_OSV_URL", "")
	require.Equal(t, osvAPIURL, newHTTPOSVClient().baseURL)
	for _, endpoint := range []string{"http://example.com/v1/query", "file:///tmp/result", "https://user:secret@example.com", "https://example.com/#fragment", ":bad"} {
		t.Run(endpoint, func(t *testing.T) {
			t.Setenv("TOOLTRUST_OSV_URL", endpoint)
			c := newHTTPOSVClient()
			_, err := c.Query(context.Background(), Dependency{Name: "fixture", Version: "1", Ecosystem: "npm"})
			require.ErrorContains(t, err, "endpoint")
		})
	}
}

func TestOSVHTTPContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer server.Close()
	c := &httpOSVClient{http: server.Client(), baseURL: server.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err := c.Query(ctx, Dependency{Name: "fixture", Version: "1", Ecosystem: "npm"})
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
