//go:build issue9

package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	bouncercfg "github.com/pastdev/agentcon/pkg/bouncer/config"
)

var errReachedSecret = errors.New("direct request succeeded; the agent reached the secret without bouncer")

func runAgent(svcURL string) error {
	svcURL = strings.TrimRight(svcURL, "/")
	placeholder := bouncercfg.Placeholder(credName)
	viaProxy := &http.Client{Timeout: 15 * time.Second}
	direct := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{Proxy: nil},
	}

	fmt.Printf("agent holds Authorization: Bearer %s\n", placeholder)
	fmt.Printf("HTTP_PROXY=%s\n\n", os.Getenv("HTTP_PROXY"))

	fmt.Println("1. agent -> service directly (no proxy)")
	err := probe(direct, svcURL+"/secret", placeholder)
	if errors.Is(err, errReachedSecret) {
		return err
	}
	if err != nil {
		fmt.Printf("   isolated (no route): %v\n", err)
	}

	fmt.Println("2. agent -> bouncer -> /secret")
	err = expect(viaProxy, svcURL+"/secret", placeholder, http.StatusOK, taggedBody)
	if err != nil {
		return err
	}
	fmt.Println("   bouncer injected the token, TS filter tagged the body via smoke-tag")

	fmt.Println("3. agent -> bouncer -> /secret?raw=1")
	err = expect(viaProxy, svcURL+"/secret?raw=1", placeholder, http.StatusForbidden, filterDenied)
	if err != nil {
		return err
	}
	fmt.Println("   TS filter denied a request the path rule would allow")

	fmt.Println("4. agent -> bouncer -> /other")
	err = expect(viaProxy, svcURL+"/other", placeholder, http.StatusForbidden, "")
	if err != nil {
		return err
	}
	fmt.Println("   path denied")

	fmt.Println("5. agent -> bouncer -> http://example.com/")
	err = expect(viaProxy, "http://example.com/", placeholder, http.StatusForbidden, "")
	if err != nil {
		return err
	}
	fmt.Println("   unmatched host denied")
	fmt.Println("\nok")
	return nil
}

func probe(client *http.Client, rawURL, placeholder string) error {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+placeholder)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("direct: %w", err)
	}
	_ = resp.Body.Close()
	fmt.Printf("   HTTP %d\n", resp.StatusCode)
	if resp.StatusCode == http.StatusOK {
		return errReachedSecret
	}
	fmt.Println("   reached the host but the placeholder was rejected")
	return nil
}
