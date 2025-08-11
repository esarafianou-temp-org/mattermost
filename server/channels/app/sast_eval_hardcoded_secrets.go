// SAST EVALUATION FILE - Hardcoded Secrets Detection Challenges
// WARNING: This file contains intentional security vulnerabilities for SAST tool evaluation
// DO NOT MERGE - This code is unsafe and should never be used in production

package app

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
)

/**
 * HARDCODED SECRETS DETECTION CHALLENGES
 *
 * These examples test SAST tools' ability to detect hardcoded secrets while
 * avoiding false positives. Tests address limitations from "Hardcoded secrets"
 * section: language/naming challenges and entropy evaluation.
 */

// =============================================================================
// TRUE POSITIVES - These SHOULD be detected as hardcoded secrets
// =============================================================================

// VULNERABLE: Obvious hardcoded database password
const DATABASE_PASSWORD = "MySecretP@ssw0rd123!"
const API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
const JWT_SECRET = "super-secret-jwt-signing-key-2024"

// VULNERABLE: AWS credentials (common pattern)
func connectToAWS() {
	awsAccessKey := "AKIAIOSFODNN7EXAMPLE"
	awsSecretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	// Use credentials (simulated)
	fmt.Printf("Connecting with access key: %s\n", awsAccessKey)
}

// VULNERABLE: Database connection with hardcoded credentials
func connectToDatabase() (*sql.DB, error) {
	// SECURITY FLAW: Hardcoded database credentials
	connectionString := "postgres://admin:VerySecretPassword123@localhost:5432/mattermost"
	return sql.Open("postgres", connectionString)
}

// VULNERABLE: API authentication token
type APIClient struct {
	baseURL string
	token   string
}

func newAPIClient() *APIClient {
	return &APIClient{
		baseURL: "https://api.example.com",
		token:   "bearer_abc123def456ghi789jkl012mno345pqr678", // HARDCODED SECRET
	}
}

// =============================================================================
// FALSE POSITIVES - These should NOT be detected (but often are)
// =============================================================================

// Language challenge: Spanish variable names (item 1 from notes)
const contraseña = "no-es-secreto"     // "password" in Spanish, but not a real secret
const usuario = "admin-user"           // "user" in Spanish
const clave = "public-encryption-algo" // "key" in Spanish, but algorithm name

// Language challenge: Portuguese variable names
const senha = "reset-instructions"    // "password" in Portuguese, but help text
const segredo = "public-demo-content" // "secret" in Portuguese, but demo data

// Misleading English words containing "pass" (item 1 from notes)
const secretary = "executive-assistant"                // Contains "secret" but role name
const compass = "/icons/compass-north.svg"             // Contains "pass" but file path
const password_reset_url = "https://example.com/reset" // Contains "password" but URL
const bypass_validation = true                         // Contains "pass" but boolean flag
const surpass_limit = 1000                             // Contains "pass" but numeric limit

// Common false positive patterns
const encryption_key_type = "AES-256"                    // Contains "key" but algorithm name
const secret_santa_list = "participants.json"            // Contains "secret" but feature name
const password_policy_url = "https://company.com/policy" // Contains "password" but URL

// Technical terms that aren't secrets
const master_branch = "main"        // Contains "master" but git branch
const private_key_algorithm = "RSA" // Contains "key" but algorithm type
const token_expiry_hours = 24       // Contains "token" but configuration

// =============================================================================
// FALSE NEGATIVES - These ARE secrets but may be missed (advanced detection)
// =============================================================================

// Low entropy secrets (item 2 from notes) - Real secrets but look innocuous
const defaultAdminPassword = "admin"      // REAL SECRET but low entropy
const initialPassword = "password123"     // REAL SECRET but common pattern
const temporaryToken = "CHANGEME"         // REAL SECRET but placeholder-like
const developmentApiKey = "dev-key-12345" // REAL SECRET but looks like placeholder

// Obfuscated or encoded secrets that might be missed
const encodedSecret = "YWRtaW46cGFzc3dvcmQxMjM=" // base64("admin:password123") - REAL SECRET
const hexEncodedKey = "61646d696e3a706173737764" // hex("admin:passwd") - REAL SECRET

// Split secrets across variables (challenging for SAST)
const dbHost = "production-database.internal"
const dbUser = "admin"
const dbPass = "ProductionSecret2024!" // REAL SECRET but separated from context
const dbPort = "5432"

func connectToSplitConfigDB() {
	// VULNERABLE: Real secret but split across multiple variables
	conn := fmt.Sprintf("host=%s user=%s password=%s port=%s", dbHost, dbUser, dbPass, dbPort)
	fmt.Println("Connection string:", conn)
}

// Secrets in non-obvious variable names
const systemConfiguration = "Bearer sk-prod-abc123def456"                    // REAL SECRET, misleading name
const applicationSettings = "mysql://root:RootPassword2024@prod-db:3306/app" // REAL SECRET

// Concatenated secrets that look like configuration
func buildConnectionString() string {
	prefix := "mongodb://"
	credentials := "admin:MongoSecret123!" // REAL SECRET
	suffix := "@cluster.mongodb.net/app"
	return prefix + credentials + suffix
}

// =============================================================================
// CONTEXT-DEPENDENT EXAMPLES
// =============================================================================

// Environment-specific secrets (should be flagged in production contexts)
func getConfiguration(environment string) map[string]string {
	switch environment {
	case "development":
		return map[string]string{
			"api_key": "dev-key-not-secret", // Acceptable for dev
			"db_pass": "dev-password",       // Acceptable for dev
		}
	case "production":
		// VULNERABLE: Hardcoded production secrets
		return map[string]string{
			"api_key": "prod-sk-1a2b3c4d5e6f", // REAL SECRET
			"db_pass": "ProdSecretPass2024!",  // REAL SECRET
		}
	default:
		return map[string]string{}
	}
}

// Test data that might be confused for secrets
const testUserPassword = "test123"                            // Test data, not real secret
const mockApiResponse = `{"token": "fake-token-for-testing"}` // Mock data
const sampleCredentials = "demo:demo"                         // Example data in documentation

// =============================================================================
// EDGE CASES AND ADVANCED SCENARIOS
// =============================================================================

// Secrets in comments (some tools check comments, others don't)
func authenticateUser() {
	// TODO: Remove this before production - API_KEY = "live-key-abc123def456"
	/* TEMP: Using hardcoded password: "TempSecret2024!" for testing */

	// Get credentials from environment
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		// VULNERABLE: Fallback to hardcoded secret
		apiKey = "fallback-secret-key-xyz789" // REAL SECRET as fallback
	}

	fmt.Printf("Using API key: %s\n", apiKey[:10]+"...")
}

// Secrets in HTTP headers/requests
func makeAuthenticatedRequest() {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)

	// VULNERABLE: Hardcoded authorization header
	req.Header.Set("Authorization", "Bearer prod-token-987654321") // REAL SECRET
	req.Header.Set("X-API-Key", "secret-api-key-abcdef123456")     // REAL SECRET

	// Execute request (simulated)
	fmt.Printf("Making request with auth header\n")
}

// Multi-language mixed content
func configuración() {
	// Mixed language variable names with real secrets
	contraseñaReal := "ProductionPassword2024!" // REAL SECRET (Spanish var name)
	secretoVerdadero := "sk-real-abc123def456"  // REAL SECRET (Spanish var name)
	claveDeAcceso := "access-key-prod-789xyz"   // REAL SECRET (Spanish var name)

	fmt.Printf("Config loaded with credentials\n")
}
