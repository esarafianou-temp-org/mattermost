// SAST EVALUATION FILE - CWE-89 (SQL Injection) - Allowlist Limitation Example
// WARNING: This file contains intentional security vulnerabilities for SAST tool evaluation
// DO NOT MERGE - This code is unsafe and should never be used in production

package api4

import (
	"database/sql"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/v8/channels/web"
)

/**
 * Custom "sanitization" function that appears to validate input
 * but has security flaws that SAST tools may not detect
 */
func validateColumnName(columnName string) bool {
	// Allow list of "safe" column names - appears to be secure
	allowedColumns := []string{
		"id", "username", "email", "first_name", "last_name", 
		"create_at", "update_at", "nickname", "position",
	}
	
	for _, allowed := range allowedColumns {
		if columnName == allowed {
			return true
		}
	}
	return false
}

/**
 * Custom input cleaning function that removes some dangerous characters
 * but is insufficient for complete protection
 */
func cleanSortDirection(direction string) string {
	// Remove some SQL injection characters but not all
	cleaned := strings.ReplaceAll(direction, ";", "")
	cleaned = strings.ReplaceAll(cleaned, "--", "")
	cleaned = strings.ReplaceAll(cleaned, "/*", "")
	cleaned = strings.ReplaceAll(cleaned, "*/", "")
	
	// Basic validation - only allow ASC or DESC
	cleaned = strings.ToUpper(strings.TrimSpace(cleaned))
	if cleaned == "ASC" || cleaned == "DESC" {
		return cleaned
	}
	return "ASC" // Default to ASC if invalid
}

/**
 * SECURITY VULNERABILITY - CWE-89: SQL Injection
 * Despite Custom Validation and Allowlisting
 * 
 * This endpoint demonstrates SQL injection that persists despite apparent
 * input validation. It shows how SAST tools might be fooled by seeing
 * validation functions and allowlists, but the implementation still has flaws.
 * 
 * Vulnerabilities:
 * 1. Column names cannot be parameterized in SQL, so they're concatenated directly
 * 2. The allowlist validation can be bypassed with SQL comments and whitespace
 * 3. The sort direction cleaning is insufficient
 * 
 * Attack Vector Examples:
 * GET /api/v4/sast-eval/users/list?sort_by=username/**/UNION/**/SELECT/**/password/**/FROM/**/users--&sort_dir=ASC
 * GET /api/v4/sast-eval/users/list?sort_by=id&sort_dir=ASC;DROP/**/TABLE/**/users--
 * GET /api/v4/sast-eval/users/list?sort_by=email&sort_dir=DESC)/**/UNION/**/SELECT/**/1,2,3,4,5/**/FROM/**/sensitive_table--
 * 
 * VULNERABILITY: Inadequate input validation for SQL context
 * FIX: Use strict allowlists with exact matching and no dynamic column names,
 *      or use ORM/query builder that handles column names safely
 */
func sastEvalListUsers(c *Context, w http.ResponseWriter, r *http.Request) {
	// Extract potentially dangerous parameters
	sortBy := r.URL.Query().Get("sort_by")
	sortDir := r.URL.Query().Get("sort_dir")
	teamId := r.URL.Query().Get("team_id")

	// Set defaults
	if sortBy == "" {
		sortBy = "username"
	}
	if sortDir == "" {
		sortDir = "ASC"
	}

	// Apply "security" validation - SAST tools might think this makes it safe
	if !validateColumnName(sortBy) {
		c.Err = model.NewAppError("sastEvalListUsers", "api.user.list.invalid_column", nil, "", http.StatusBadRequest)
		return
	}

	// Apply "cleaning" to sort direction
	cleanedSortDir := cleanSortDirection(sortDir)

	// VULNERABLE CODE: Even with validation, SQL injection is still possible
	// Column names cannot be parameterized, making this vulnerable to:
	// 1. SQL comments that bypass validation (/* */)
	// 2. Unicode encoding bypasses
	// 3. Case sensitivity bypasses
	// 4. Whitespace bypasses
	query := fmt.Sprintf(`
		SELECT u.id, u.username, u.email, u.first_name, u.last_name
		FROM users u
		JOIN team_members tm ON u.id = tm.user_id
		WHERE tm.team_id = '%s'
		AND u.delete_at = 0
		ORDER BY u.%s %s
		LIMIT 100
	`, teamId, sortBy, cleanedSortDir)

	// Execute the still-vulnerable query
	db := c.App.Srv().Store.GetMaster()
	rows, err := db.Query(query)
	if err != nil {
		c.Err = model.NewAppError("sastEvalListUsers", "api.user.list.sql_error", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []*model.User
	for rows.Next() {
		user := &model.User{}
		err := rows.Scan(&user.Id, &user.Username, &user.Email, &user.FirstName, &user.LastName)
		if err != nil {
			c.Err = model.NewAppError("sastEvalListUsers", "api.user.list.scan_error", nil, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(users); err != nil {
		c.Logger.Warn("Error encoding users to JSON", mlog.Err(err))
	}
}

/**
 * Additional example showing insufficient regex-based validation
 */
func validateTableName(tableName string) bool {
	// Regex that appears secure but has bypasses
	matched, _ := regexp.MatchString(`^[a-zA-Z_][a-zA-Z0-9_]*$`, tableName)
	return matched && len(tableName) <= 50
}

func sastEvalGetTableStats(c *Context, w http.ResponseWriter, r *http.Request) {
	tableName := r.URL.Query().Get("table")
	
	// Apply regex validation - might fool SAST tools
	if !validateTableName(tableName) {
		c.Err = model.NewAppError("sastEvalGetTableStats", "api.stats.invalid_table", nil, "", http.StatusBadRequest)
		return
	}

	// STILL VULNERABLE: Table names cannot be parameterized
	// Regex validation can be bypassed with valid identifier characters
	// that form malicious SQL when concatenated
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE delete_at = 0", tableName)
	
	db := c.App.Srv().Store.GetMaster()
	var count int
	err := db.QueryRow(query).Scan(&count)
	if err != nil {
		c.Err = model.NewAppError("sastEvalGetTableStats", "api.stats.sql_error", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	result := map[string]interface{}{
		"table": tableName,
		"count": count,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func init() {
	// Register the vulnerable endpoints - these should never be merged
	// BaseRoutes.ApiRoot.Handle("/sast-eval/users/list", ApiHandler(sastEvalListUsers)).Methods("GET")
	// BaseRoutes.ApiRoot.Handle("/sast-eval/stats/table", ApiHandler(sastEvalGetTableStats)).Methods("GET")
}