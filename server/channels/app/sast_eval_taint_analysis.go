// SAST EVALUATION FILE - Taint Analysis Limitations
// WARNING: This file contains intentional security vulnerabilities for SAST tool evaluation
// DO NOT MERGE - This code is unsafe and should never be used in production

package app

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

/**
 * TAINT ANALYSIS LIMITATIONS CHALLENGES
 *
 * These examples test SAST tools' taint analysis capabilities, addressing
 * limitations from the "Taint analysis limitations" section:
 * 1. Path analysis shortcuts and data structure tainting
 * 2. Framework/library support limitations
 */

// =============================================================================
// CHALLENGE 1: Data Structure Tainting (from notes example)
// =============================================================================

// VULNERABLE: Partial slice tainting - tests if SAST tools can distinguish elements
func sastEvalSliceTainting(r *http.Request, db *sql.DB) {
	// Get tainted data from HTTP request - proper taint source
	userInput := r.URL.Query().Get("column") // TAINT SOURCE: HTTP query parameter

	// Example from notes: slice with mixed trusted/untrusted data
	columns := []string{"email", "phone", userInput} // First two are safe, third is tainted

	// Safe usage - using hardcoded elements (should NOT be flagged)
	safeQuery1 := fmt.Sprintf("SELECT %s FROM users", columns[0]) // email - safe
	safeQuery2 := fmt.Sprintf("SELECT %s FROM users", columns[1]) // phone - safe

	// VULNERABLE usage - using tainted element (SHOULD be flagged)
	vulnerableQuery := fmt.Sprintf("SELECT %s FROM users", columns[2]) // userInput - vulnerable

	// TAINT SINKS: Actually execute the queries
	db.Query(safeQuery1)      // Safe execution
	db.Query(safeQuery2)      // Safe execution
	db.Query(vulnerableQuery) // VULNERABLE: SQL injection sink
}

// VULNERABLE: Map tainting challenges
func sastEvalMapTainting(r *http.Request) {
	// Get tainted data from HTTP request - proper taint sources
	userKey := r.Header.Get("Config-Key")    // TAINT SOURCE: HTTP header
	userValue := r.FormValue("config_value") // TAINT SOURCE: Form data

	// Mixed trusted/untrusted map data
	configMap := map[string]string{
		"app_name":    "Mattermost", // Safe hardcoded value
		"server_port": "8080",       // Safe hardcoded value
		"user_pref":   userValue,    // Tainted user input
	}

	// Safe usage (should NOT be flagged)
	safeConfig1 := configMap["app_name"]    // Hardcoded key, safe value
	safeConfig2 := configMap["server_port"] // Hardcoded key, safe value

	// VULNERABLE usage (SHOULD be flagged)
	vulnerableConfig := configMap["user_pref"] // Hardcoded key, tainted value
	dynamicConfig := configMap[userKey]        // Tainted key, any value

	// TAINT SINKS: Actually execute commands in dangerous context
	command1 := exec.Command("echo", safeConfig1)          // Safe
	command2 := exec.Command("echo", safeConfig2)          // Safe
	command3 := exec.Command("sh", "-c", vulnerableConfig) // VULNERABLE: Command injection sink
	command4 := exec.Command("sh", "-c", dynamicConfig)    // VULNERABLE: Command injection sink

	// Execute the commands (actual sinks)
	command1.Run() // Safe execution
	command2.Run() // Safe execution
	command3.Run() // VULNERABLE: Command injection execution
	command4.Run() // VULNERABLE: Command injection execution
}

// VULNERABLE: Struct field tainting
type UserData struct {
	ID       int    // Safe - always from database
	Username string // Safe - validated
	Input    string // Tainted - user input
}

func sastEvalStructTainting(r *http.Request, db *sql.DB) {
	// Get tainted data from HTTP request - proper taint source
	rawInput := r.URL.Query().Get("search") // TAINT SOURCE: HTTP query parameter

	userData := UserData{
		ID:       123,
		Username: "admin",
		Input:    rawInput, // Tainted field
	}

	// Safe usage (should NOT be flagged)
	safeQuery1 := fmt.Sprintf("SELECT * FROM users WHERE id = %d", userData.ID)
	safeQuery2 := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", userData.Username)

	// VULNERABLE usage (SHOULD be flagged)
	vulnerableQuery := fmt.Sprintf("SELECT * FROM users WHERE data = '%s'", userData.Input)

	// TAINT SINKS: Actually execute the queries
	db.Query(safeQuery1)      // Safe execution
	db.Query(safeQuery2)      // Safe execution
	db.Query(vulnerableQuery) // VULNERABLE: SQL injection sink
}

// =============================================================================
// CHALLENGE 2: Complex Path Analysis
// =============================================================================

// VULNERABLE: Multi-step taint propagation with decision trees
func sastEvalComplexPath(r *http.Request, db *sql.DB, condition bool) {
	// Get tainted data from HTTP request - proper taint source
	userInput := r.PostFormValue("username") // TAINT SOURCE: POST form data

	var processedData string

	if condition {
		// Path 1: Data gets processed through multiple steps
		step1 := strings.ToUpper(userInput)
		step2 := strings.TrimSpace(step1)
		processedData = step2 // Still tainted after transformations
	} else {
		// Path 2: Safe hardcoded data
		processedData = "safe-default-value"
	}

	// TAINT SINK: Execute query with processed data
	vulnerableQuery := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", processedData)
	db.Query(vulnerableQuery) // VULNERABLE: SQL injection sink (may miss taint depending on path analysis)
}

// VULNERABLE: Taint through function calls (interprocedural analysis)
func processUserData(input string) string {
	// Simple transformation but taint should propagate
	return "processed_" + input
}

func sastEvalInterprocedural(r *http.Request) {
	// Get tainted data from HTTP request - proper taint source
	userInput := r.Header.Get("User-Agent") // TAINT SOURCE: HTTP header

	// Taint should flow through function call
	processed := processUserData(userInput) // Still tainted

	// TAINT SINK: Execute command with tainted data
	command := exec.Command("sh", "-c", processed) // Command injection
	command.Run()                                  // VULNERABLE: Command injection execution
}

// =============================================================================
// CHALLENGE 3: Framework/Library Support Limitations
// =============================================================================

// VULNERABLE: HTTP request handling (tests framework support)
func sastEvalHTTPFramework(w http.ResponseWriter, r *http.Request) {
	// Standard library sources - should be well supported
	userAgent := r.Header.Get("User-Agent")   // Taint source
	queryParam := r.URL.Query().Get("search") // Taint source
	postData := r.FormValue("data")           // Taint source

	// TAINT SINKS: Execute commands with tainted data
	command1 := exec.Command("sh", "-c", userAgent)  // Command injection
	command2 := exec.Command("sh", "-c", queryParam) // Command injection
	command3 := exec.Command("sh", "-c", postData)   // Command injection

	// Execute the commands (actual sinks)
	command1.Run() // VULNERABLE: Command injection execution
	command2.Run() // VULNERABLE: Command injection execution
	command3.Run() // VULNERABLE: Command injection execution
}

// VULNERABLE: Database operations (SQL injection testing)
func sastEvalDatabaseFramework(db *sql.DB, r *http.Request) {
	// Get tainted data from HTTP request - proper taint source
	userInput := r.URL.Query().Get("filter") // TAINT SOURCE: HTTP query parameter

	// Different ways to construct queries - tests SQL injection detection

	// Direct concatenation (should be detected)
	query1 := "SELECT * FROM users WHERE name = '" + userInput + "'"

	// sprintf (should be detected)
	query2 := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userInput)

	// String builder pattern (may be missed)
	var builder strings.Builder
	builder.WriteString("SELECT * FROM users WHERE email = '")
	builder.WriteString(userInput) // Tainted
	builder.WriteString("'")
	query3 := builder.String()

	// TAINT SINKS: Execute queries (all vulnerable to SQL injection)
	db.Query(query1) // VULNERABLE: SQL injection sink
	db.Query(query2) // VULNERABLE: SQL injection sink
	db.Query(query3) // VULNERABLE: SQL injection sink
}

// VULNERABLE: Database as taint source (data from database used unsafely)
func sastEvalDatabaseTaintSource(db *sql.DB) {
	// Database data as taint source - data from database is untrusted
	var userContent string
	row := db.QueryRow("SELECT user_content FROM posts WHERE id = 1")
	row.Scan(&userContent) // TAINT SOURCE: Database data (user-generated content)

	// TAINT SINK: Execute command with database content
	command := exec.Command("sh", "-c", "echo "+userContent) // Command injection
	command.Run()                                            // VULNERABLE: Command injection execution
}

// VULNERABLE: File system operations
func sastEvalFileSystemFramework(r *http.Request) {
	// Get tainted data from HTTP request - proper taint source
	userPath := r.URL.Query().Get("file") // TAINT SOURCE: HTTP query parameter

	// Different file operations - tests path traversal detection

	// TAINT SINKS: File operations with tainted paths
	file1, _ := os.Open(userPath)                   // VULNERABLE: Path traversal sink
	file2, _ := os.Create("/tmp/" + userPath)       // VULNERABLE: Path traversal sink
	content, _ := os.ReadFile("config/" + userPath) // VULNERABLE: Path traversal sink

	// Use the files to ensure they're executed
	if file1 != nil {
		file1.Close()
	}
	if file2 != nil {
		file2.Close()
	}
	if len(content) > 0 {
		// File was read successfully
	}
}

// =============================================================================
// EDGE CASES: Testing SAST Tool Sophistication
// =============================================================================

// VULNERABLE: Nested data structures
func sastEvalNestedTainting(r *http.Request) {
	// Get tainted data from HTTP request - proper taint source
	userInput := r.FormValue("nested_data") // TAINT SOURCE: Form data

	// Nested slice with tainted element
	nestedData := [][]string{
		{"safe", "values"},
		{"more", "safe", "data"},
		{"mixed", userInput}, // This inner slice has tainted element
	}

	// Safe usage
	safeValue := nestedData[0][0] // "safe"

	// VULNERABLE usage
	taintedValue := nestedData[2][1] // userInput

	// TAINT SINKS: Execute commands in dangerous context
	command1 := exec.Command("echo", safeValue)          // Safe
	command2 := exec.Command("sh", "-c", taintedValue)   // VULNERABLE: Command injection sink
	
	// Execute the commands (actual sinks)
	command1.Run() // Safe execution
	command2.Run() // VULNERABLE: Command injection execution
}

// VULNERABLE: Taint propagation through channels (Go-specific)
func sastEvalChannelTainting(r *http.Request) {
	// Get tainted data from HTTP request - proper taint source
	userInput := r.Header.Get("X-Custom-Command") // TAINT SOURCE: HTTP header

	ch := make(chan string, 1)
	ch <- userInput // Send tainted data

	// Receive tainted data
	received := <-ch // Should still be tainted

	// TAINT SINK: Execute command with tainted data from channel
	command := exec.Command("sh", "-c", received) // Command injection
	command.Run() // VULNERABLE: Command injection execution
}
