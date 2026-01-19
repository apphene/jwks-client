package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// DefaultRefreshInterval is the default interval at which the JWKS is refreshed
	DefaultRefreshInterval = 1 * time.Minute

	// DefaultRetryInterval is the default interval at which the JWKS is retried if the fetch fails
	DefaultRetryInterval = 3 * time.Second

	// DefaultRetryCount is the number of times to retry the JWKS fetch if it fails
	DefaultRetryCount = 3
)

type Option func(*JwksAuthority)

type JwksAuthority struct {
	url string

	keys            []*Key
	mu              sync.RWMutex
	refreshInterval time.Duration
	retryInterval   time.Duration
	retryCount      int
}

func NewJwksAuthority(ctx context.Context, url string, opts ...Option) (*JwksAuthority, error) {
	authority := &JwksAuthority{
		url:             url,
		mu:              sync.RWMutex{},
		refreshInterval: DefaultRefreshInterval,
		keys:            make([]*Key, 0),
		retryInterval:   DefaultRetryInterval,
		retryCount:      DefaultRetryCount,
	}

	for _, opt := range opts {
		opt(authority)
	}

	err := authority.fetchKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch initial keys: %w", err)
	}

	go authority.background(ctx)

	return authority, nil
}

func (j *JwksAuthority) background(ctx context.Context) {
	ticker := time.NewTicker(j.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for i := 0; i < j.retryCount; i++ {
				err := j.fetchKeys(ctx)
				if err != nil {
					time.Sleep(j.retryInterval)
					continue
				}
				break
			}
		}
	}
}

func (j *JwksAuthority) fetchKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", j.url, nil)
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS body: %w", err)
	}

	keys := struct {
		Keys []*Key `json:"keys"`
	}{}
	err = json.Unmarshal(body, &keys)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JWKS: %w", err)
	}

	for _, key := range keys.Keys {
		err := key.resolvePublicKey()
		if err != nil {
			return fmt.Errorf("failed to resolve public key: %w", err)
		}
	}

	j.mu.Lock()
	j.keys = keys.Keys
	j.mu.Unlock()

	return nil
}

func (j *JwksAuthority) Validate(ctx context.Context, tokenBytes []byte) (*jwt.Token, error) {
	// Parse the token to get the header (without validation)
	token, err := jwt.Parse(string(tokenBytes), func(token *jwt.Token) (interface{}, error) {
		// Get the kid from the token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not found in token header")
		}

		// Find the matching key
		key, err := j.getKey(kid)
		if err != nil {
			return nil, fmt.Errorf("failed to get key: %w", err)
		}

		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return key.publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}))

	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	return token, nil
}

func (j *JwksAuthority) getKey(kid string) (*Key, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	for _, key := range j.keys {
		if key.Kid == kid {
			return key, nil
		}
	}

	return nil, fmt.Errorf("key with kid %s not found in JWKS", kid)
}
