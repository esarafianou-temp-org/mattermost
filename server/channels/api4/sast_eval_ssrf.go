// SAST EVALUATION FILE - Server-Side Request Forgery (SSRF)
// WARNING: This file contains intentional security vulnerabilities for SAST tool evaluation
// DO NOT MERGE - This code is unsafe and should never be used in production

package api4

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
)

/**
 * SECURITY VULNERABILITY - Server-Side Request Forgery (SSRF)
 * 
 * These endpoints demonstrate SSRF vulnerabilities where user-controlled URLs
 * are used to make HTTP requests from the server. This allows attackers to:
 * 1. Access internal services (localhost, 127.0.0.1, internal IPs)
 * 2. Scan internal networks
 * 3. Access cloud metadata endpoints (AWS, GCP, Azure)
 * 4. Bypass firewalls and access controls
 * 5. Perform port scanning
 * 
 * VULNERABILITY: Server makes HTTP requests to user-controlled URLs without validation
 * FIX: Implement URL allowlists, block internal IPs, validate schemes, use DNS resolution checks
 */

// VULNERABLE: Direct SSRF - fetches any URL provided by user
func sastEvalFetchURL(c *Context, w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")

	if targetURL == "" {
		c.Err = model.NewAppError("sastEvalFetchURL", "api.ssrf.missing_url", nil, "", http.StatusBadRequest)
		return
	}

	// VULNERABLE: No validation of target URL
	// Attack vectors:
	// - http://localhost:8080/admin (access internal admin interfaces)
	// - http://127.0.0.1:6379/ (access internal Redis)
	// - http://169.254.169.254/latest/meta-data/ (AWS metadata)
	// - file:///etc/passwd (local file access if supported)
	// - http://internal-database:5432/ (internal service discovery)
	
	c.Logger.Warn("SAST EVAL: Making request to user-provided URL", 
		map[string]interface{}{
			"target_url": targetURL,
			"user_id":    c.AppContext.Session().UserId,
		})

	// Create HTTP client with timeout (good practice but doesn't fix SSRF)
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// VULNERABLE: Direct request to user-controlled URL
	resp, err := client.Get(targetURL)
	if err != nil {
		c.Err = model.NewAppError("sastEvalFetchURL", "api.ssrf.request_failed", nil, err.Error(), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	// Read response body (could contain sensitive internal data)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.Err = model.NewAppError("sastEvalFetchURL", "api.ssrf.read_failed", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the response to user (information disclosure)
	response := map[string]interface{}{
		"status_code": resp.StatusCode,
		"headers":     resp.Header,
		"body":        string(body),
		"url":         targetURL,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// VULNERABLE: SSRF in webhook/callback functionality
func sastEvalRegisterWebhook(c *Context, w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		CallbackURL string `json:"callback_url"`
		EventType   string `json:"event_type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		c.Err = model.NewAppError("sastEvalRegisterWebhook", "api.ssrf.invalid_json", nil, err.Error(), http.StatusBadRequest)
		return
	}

	if requestBody.CallbackURL == "" {
		c.Err = model.NewAppError("sastEvalRegisterWebhook", "api.ssrf.missing_callback", nil, "", http.StatusBadRequest)
		return
	}

	// VULNERABLE: Test webhook by making request to user-provided callback URL
	// This is a common SSRF vector in webhook registration endpoints
	testPayload := map[string]interface{}{
		"event":     "test",
		"timestamp": time.Now().Unix(),
		"data":      "webhook registration test",
	}

	payloadBytes, _ := json.Marshal(testPayload)

	// VULNERABLE: HTTP POST to user-controlled URL
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(requestBody.CallbackURL, "application/json", strings.NewReader(string(payloadBytes)))
	
	var webhookTestResult string
	if err != nil {
		webhookTestResult = fmt.Sprintf("Webhook test failed: %v", err)
	} else {
		defer resp.Body.Close()
		webhookTestResult = fmt.Sprintf("Webhook test successful, status: %d", resp.StatusCode)
	}

	response := map[string]interface{}{
		"success":           true,
		"webhook_id":        "webhook_123", // Simulated
		"callback_url":      requestBody.CallbackURL,
		"event_type":        requestBody.EventType,
		"test_result":       webhookTestResult,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// VULNERABLE: SSRF in URL preview/unfurling functionality
func sastEvalPreviewURL(c *Context, w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		URL string `json:"url"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		c.Err = model.NewAppError("sastEvalPreviewURL", "api.ssrf.invalid_json", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Basic URL parsing (insufficient validation)
	parsedURL, err := url.Parse(requestBody.URL)
	if err != nil {
		c.Err = model.NewAppError("sastEvalPreviewURL", "api.ssrf.invalid_url", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// INSUFFICIENT: Only checking scheme, not blocking internal IPs
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		c.Err = model.NewAppError("sastEvalPreviewURL", "api.ssrf.invalid_scheme", nil, "", http.StatusBadRequest)
		return
	}

	// STILL VULNERABLE: Can access internal networks
	// Examples that would still work:
	// - http://localhost:8080/admin
	// - http://192.168.1.1/config
	// - http://10.0.0.1:3306/
	
	client := &http.Client{
		Timeout: 10 * time.Second,
		// Should add custom transport to block internal IPs, but doesn't
	}

	resp, err := client.Get(requestBody.URL)
	if err != nil {
		c.Err = model.NewAppError("sastEvalPreviewURL", "api.ssrf.fetch_failed", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Extract title and description for URL preview
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.Err = model.NewAppError("sastEvalPreviewURL", "api.ssrf.read_failed", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Simple HTML parsing for title (vulnerable to additional attacks)
	title := extractTitle(string(body))
	
	response := map[string]interface{}{
		"url":         requestBody.URL,
		"title":       title,
		"status_code": resp.StatusCode,
		"accessible":  true,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Helper function for URL preview
func extractTitle(html string) string {
	// Simple title extraction (not the focus of this SSRF example)
	start := strings.Index(strings.ToLower(html), "<title>")
	if start == -1 {
		return "No title found"
	}
	start += 7
	end := strings.Index(strings.ToLower(html[start:]), "</title>")
	if end == -1 {
		return "No title found"
	}
	return html[start : start+end]
}

// Example of secure implementation patterns (commented out):
// import "net"
//
// func isInternalIP(host string) bool {
//     // SECURE: Block internal/private IP ranges
//     ip := net.ParseIP(host)
//     if ip == nil {
//         return false
//     }
//     
//     // Block localhost
//     if ip.IsLoopback() {
//         return true
//     }
//     
//     // Block private networks
//     if ip.IsPrivate() {
//         return true
//     }
//     
//     // Block link-local
//     if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
//         return true
//     }
//     
//     return false
// }
//
// func validateURL(targetURL string) error {
//     // SECURE: Parse and validate URL
//     parsedURL, err := url.Parse(targetURL)
//     if err != nil {
//         return err
//     }
//     
//     // Allow only HTTP/HTTPS
//     if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
//         return errors.New("invalid scheme")
//     }
//     
//     // Resolve hostname to IP and check if internal
//     host := parsedURL.Hostname()
//     if isInternalIP(host) {
//         return errors.New("internal IP not allowed")
//     }
//     
//     // Additional checks for DNS resolution
//     ips, err := net.LookupIP(host)
//     if err != nil {
//         return err
//     }
//     
//     for _, ip := range ips {
//         if isInternalIP(ip.String()) {
//             return errors.New("hostname resolves to internal IP")
//         }
//     }
//     
//     return nil
// }

func init() {
	// Register the vulnerable endpoints - these should never be merged
	// BaseRoutes.ApiRoot.Handle("/sast-eval/fetch-url", ApiHandler(sastEvalFetchURL)).Methods("GET")
	// BaseRoutes.ApiRoot.Handle("/sast-eval/register-webhook", ApiHandler(sastEvalRegisterWebhook)).Methods("POST")
	// BaseRoutes.ApiRoot.Handle("/sast-eval/preview-url", ApiHandler(sastEvalPreviewURL)).Methods("POST")
}