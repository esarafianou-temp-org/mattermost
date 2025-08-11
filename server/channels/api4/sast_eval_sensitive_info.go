// SAST EVALUATION FILE - Sensitive Information Exposure
// WARNING: This file contains intentional security vulnerabilities for SAST tool evaluation
// DO NOT MERGE - This code is unsafe and should never be used in production

package api4

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/mattermost/mattermost/server/public/model"
)

/**
 * SENSITIVE INFORMATION EXPOSURE CHALLENGES
 * 
 * These examples test SAST tools' ability to identify sensitive information
 * exposure as outlined in the "Identifying sensitive information" section:
 * - CWE-201: Insertion of Sensitive Information Into Sent Data
 * - CWE-209: Generation of Error Message Containing Sensitive Information
 * - Environment variable sensitivity challenges
 */

// =============================================================================
// CWE-201: Sensitive Information in HTTP Responses (TRUE POSITIVES)
// =============================================================================

// VULNERABLE: Exposing API key in HTTP response
func sastEvalGetUserConfig(c *Context, w http.ResponseWriter, r *http.Request) {
	apiSecret := os.Getenv("API_SECRET_KEY") // Should be sensitive
	fromEmail := os.Getenv("FROM_EMAIL")     // Less sensitive

	// VULNERABILITY: Including sensitive env var in response
	response := map[string]interface{}{
		"user_id":     c.AppContext.Session().UserId,
		"api_secret":  apiSecret, // CWE-201: Sensitive info in sent data
		"from_email":  fromEmail, // Less concerning but still exposure
		"server_info": "Mattermost Dev Server",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// VULNERABLE: Database credentials in debug response
func sastEvalDebugInfo(c *Context, w http.ResponseWriter, r *http.Request) {
	dbHost := os.Getenv("DB_HOST")         // Infrastructure info
	dbPassword := os.Getenv("DB_PASSWORD") // Highly sensitive
	smtpHost := os.Getenv("SMTP_HOST")     // Infrastructure info
	smtpUser := os.Getenv("SMTP_USER")     // Credentials

	debugInfo := map[string]interface{}{
		"database": map[string]string{
			"host":     dbHost,
			"password": dbPassword, // CWE-201: Highly sensitive
		},
		"email": map[string]string{
			"smtp_host": smtpHost, // Infrastructure (less sensitive)
			"smtp_user": smtpUser, // Credentials (sensitive)
		},
		"timestamp": "2024-01-01T00:00:00Z",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(debugInfo)
}

// =============================================================================
// CWE-209: Sensitive Information in Error Messages (TRUE POSITIVES)
// =============================================================================

// VULNERABLE: Database credentials in error messages
func sastEvalConnectDatabase(c *Context, w http.ResponseWriter, r *http.Request) {
	dbUrl := os.Getenv("DATABASE_URL") // Contains credentials
	
	// Simulate database connection error
	err := fmt.Errorf("failed to connect to database: %s", dbUrl)
	
	// VULNERABILITY: Exposing database URL with credentials in error
	c.Err = model.NewAppError(
		"sastEvalConnectDatabase",
		"api.database.connection_failed",
		nil,
		err.Error(), // CWE-209: Database URL with credentials in error message
		http.StatusInternalServerError,
	)
}

// VULNERABLE: API keys in error responses
func sastEvalAuthenticateExternal(c *Context, w http.ResponseWriter, r *http.Request) {
	externalApiKey := os.Getenv("EXTERNAL_API_KEY")
	
	// Simulate authentication failure
	errorMsg := fmt.Sprintf("Authentication failed with key: %s for external service", externalApiKey)
	
	// VULNERABILITY: API key leaked in error message
	c.Err = model.NewAppError(
		"sastEvalAuthenticateExternal",
		"api.external.auth_failed",
		nil,
		errorMsg, // CWE-209: API key in error message
		http.StatusUnauthorized,
	)
}

// =============================================================================
// ENVIRONMENT VARIABLE SENSITIVITY CHALLENGES (CONTEXT-DEPENDENT)
// =============================================================================

// VULNERABLE: Mixed sensitivity - some env vars are sensitive, others aren't
func sastEvalGetAppSettings(c *Context, w http.ResponseWriter, r *http.Request) {
	// Non-sensitive environment variables (should not trigger CWE-201)
	appName := os.Getenv("APP_NAME")               // Application name
	serverPort := os.Getenv("SERVER_PORT")         // Port number
	fromEmail := os.Getenv("FROM_EMAIL_ADDRESS")   // From email (less sensitive)
	timeZone := os.Getenv("DEFAULT_TIMEZONE")      // Timezone setting
	
	// Sensitive environment variables (should trigger CWE-201)
	jwtSecret := os.Getenv("JWT_SIGNING_KEY")      // Signing key (highly sensitive)
	apiKey := os.Getenv("THIRD_PARTY_API_KEY")     // API credentials (sensitive)
	dbPassword := os.Getenv("DATABASE_PASSWORD")   // Database password (sensitive)
	
	// MIXED VULNERABILITY: Some sensitive, some not
	settings := map[string]interface{}{
		"app_name":    appName,     // OK to expose
		"server_port": serverPort,  // OK to expose
		"from_email":  fromEmail,   // Debatable - less sensitive
		"timezone":    timeZone,    // OK to expose
		"jwt_secret":  jwtSecret,   // CWE-201: Sensitive
		"api_key":     apiKey,      // CWE-201: Sensitive
		"db_password": dbPassword,  // CWE-201: Highly sensitive
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

// =============================================================================
// FALSE POSITIVES - Non-sensitive data that shouldn't trigger warnings
// =============================================================================

// Should NOT trigger CWE-201 - legitimate configuration exposure
func sastEvalGetPublicConfig(c *Context, w http.ResponseWriter, r *http.Request) {
	// These are legitimate to expose and shouldn't be flagged as sensitive
	siteName := os.Getenv("SITE_NAME")           // Public site name
	supportEmail := os.Getenv("SUPPORT_EMAIL")   // Public support contact
	version := os.Getenv("APP_VERSION")          // Application version
	environment := os.Getenv("ENVIRONMENT")      // Environment name (dev/prod)
	
	publicConfig := map[string]interface{}{
		"site_name":     siteName,
		"support_email": supportEmail,
		"version":       version,
		"environment":   environment,
		"features": map[string]bool{
			"chat_enabled":  true,
			"files_enabled": true,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(publicConfig)
}

// Should NOT trigger CWE-209 - safe error messages
func sastEvalSafeError(c *Context, w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("input")
	
	if userInput == "" {
		// SAFE: Generic error message without sensitive details
		c.Err = model.NewAppError(
			"sastEvalSafeError",
			"api.input.required",
			nil,
			"Input parameter is required", // Safe error message
			http.StatusBadRequest,
		)
		return
	}
	
	// Simulate processing
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// =============================================================================
// EDGE CASES - Testing SAST tool sophistication
// =============================================================================

// VULNERABLE: Conditional sensitive exposure (advanced detection)
func sastEvalConditionalExposure(c *Context, w http.ResponseWriter, r *http.Request) {
	debugMode := r.URL.Query().Get("debug") == "true"
	apiKey := os.Getenv("API_KEY")
	
	response := map[string]interface{}{
		"status": "ok",
		"user":   c.AppContext.Session().UserId,
	}
	
	if debugMode {
		// VULNERABILITY: Conditional exposure of sensitive data
		response["debug_info"] = map[string]interface{}{
			"api_key": apiKey, // CWE-201: Only exposed in debug mode
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// VULNERABLE: Sensitive data in logs (may be missed by some tools)
func sastEvalLogSensitiveData(c *Context, w http.ResponseWriter, r *http.Request) {
	userToken := r.Header.Get("Authorization")
	apiSecret := os.Getenv("API_SECRET")
	
	// VULNERABILITY: Logging sensitive information
	c.Logger.Info("User authentication attempt", 
		map[string]interface{}{
			"user_token":  userToken,  // User's auth token (sensitive)
			"api_secret":  apiSecret,  // System secret (sensitive)
			"endpoint":    "/sast-eval/log-test",
			"timestamp":   "2024-01-01T00:00:00Z",
		})
	
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged successfully"))
}

// Example of secure implementation (commented out):
// func secureGetConfig(c *Context, w http.ResponseWriter, r *http.Request) {
//     // SECURE: Only expose non-sensitive configuration
//     publicConfig := map[string]interface{}{
//         "app_name":     "Mattermost",
//         "version":      "8.0.0",
//         "environment":  "production",
//         // No secrets, credentials, or sensitive env vars
//     }
//     
//     w.Header().Set("Content-Type", "application/json")
//     json.NewEncoder(w).Encode(publicConfig)
// }
//
// func secureErrorHandling(c *Context, w http.ResponseWriter, r *http.Request) {
//     // SECURE: Generic error without sensitive details
//     c.Err = model.NewAppError(
//         "secureOperation", 
//         "api.operation.failed",
//         nil,
//         "Operation failed", // No sensitive information
//         http.StatusInternalServerError,
//     )
// }

func init() {
	// Register the vulnerable endpoints - these should never be merged
	// BaseRoutes.ApiRoot.Handle("/sast-eval/user-config", ApiHandler(sastEvalGetUserConfig)).Methods("GET")
	// BaseRoutes.ApiRoot.Handle("/sast-eval/debug-info", ApiHandler(sastEvalDebugInfo)).Methods("GET")
	// BaseRoutes.ApiRoot.Handle("/sast-eval/connect-db", ApiHandler(sastEvalConnectDatabase)).Methods("POST")
	// BaseRoutes.ApiRoot.Handle("/sast-eval/auth-external", ApiHandler(sastEvalAuthenticateExternal)).Methods("POST")
}