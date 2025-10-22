package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "valid API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123xyz"},
			},
			expectedKey:   "abc123xyz",
			expectedError: nil,
		},
		{
			name:          "no authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123xyz"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "malformed header - only ApiKey without key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "valid API key with extra spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key-123"},
			},
			expectedKey:   "my-secret-key-123",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			if tt.expectedError != nil {
				if err == nil {
					t.Errorf("expected error %q, got nil", tt.expectedError.Error())
				} else if err.Error() != tt.expectedError.Error() {
					t.Errorf("expected error %q, got %q", tt.expectedError.Error(), err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %q", err.Error())
				}
			}
		})
	}
}
