// SAST EVALUATION FILE - CWE-89 (SQL Injection) - Basic Example
// WARNING: This file contains intentional security vulnerabilities for SAST tool evaluation
// DO NOT MERGE - This code is unsafe and should never be used in production

package api4

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/v8/channels/web"
)

/**
 * SECURITY VULNERABILITY - CWE-89: SQL Injection
 * 
 * This endpoint demonstrates a classic SQL injection vulnerability by directly
 * concatenating user input into SQL queries without proper parameterization.
 * 
 * Attack Vector Examples:
 * GET /api/v4/sast-eval/users/search?username=admin'; DROP TABLE users; --
 * GET /api/v4/sast-eval/users/search?username=' OR 1=1 --
 * GET /api/v4/sast-eval/users/search?username=' UNION SELECT password FROM users WHERE username='admin' --
 * 
 * VULNERABILITY: Direct string concatenation in SQL queries
 * FIX: Use parameterized queries or prepared statements
 */
func sastEvalSearchUsers(c *Context, w http.ResponseWriter, r *http.Request) {
	// Extract user input from query parameter - this is untrusted data
	username := r.URL.Query().Get("username")
	teamId := r.URL.Query().Get("team_id")

	if username == "" {
		c.Err = model.NewAppError("sastEvalSearchUsers", "api.user.search.missing_username", nil, "", http.StatusBadRequest)
		return
	}

	// VULNERABLE CODE: Direct string concatenation into SQL query
	// This allows arbitrary SQL injection through the username parameter
	query := fmt.Sprintf(`
		SELECT u.id, u.username, u.email, u.first_name, u.last_name
		FROM users u
		JOIN team_members tm ON u.id = tm.user_id
		WHERE u.username LIKE '%%%s%%'
		AND tm.team_id = '%s'
		AND u.delete_at = 0
		ORDER BY u.username
		LIMIT 50
	`, username, teamId)

	// Execute the vulnerable query
	db := c.App.Srv().Store.GetMaster() // Get database connection
	rows, err := db.Query(query)
	if err != nil {
		c.Err = model.NewAppError("sastEvalSearchUsers", "api.user.search.sql_error", nil, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []*model.User
	for rows.Next() {
		user := &model.User{}
		err := rows.Scan(&user.Id, &user.Username, &user.Email, &user.FirstName, &user.LastName)
		if err != nil {
			c.Err = model.NewAppError("sastEvalSearchUsers", "api.user.search.scan_error", nil, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	// Return the results (potentially including unauthorized data from SQL injection)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(users); err != nil {
		c.Logger.Warn("Error encoding users to JSON", mlog.Err(err))
	}
}

// Example of safe implementation (commented out):
// func safeSearchUsers(c *Context, w http.ResponseWriter, r *http.Request) {
//     username := r.URL.Query().Get("username")
//     teamId := r.URL.Query().Get("team_id")
//
//     // SAFE: Use parameterized query
//     query := `
//         SELECT u.id, u.username, u.email, u.first_name, u.last_name
//         FROM users u
//         JOIN team_members tm ON u.id = tm.user_id
//         WHERE u.username LIKE $1
//         AND tm.team_id = $2
//         AND u.delete_at = 0
//         ORDER BY u.username
//         LIMIT 50
//     `
//
//     db := c.App.Srv().Store.GetMaster()
//     rows, err := db.Query(query, "%"+username+"%", teamId)
//     // ... rest of implementation
// }

func init() {
	// Register the vulnerable endpoint - this should never be merged
	// BaseRoutes.ApiRoot.Handle("/sast-eval/users/search", ApiHandler(sastEvalSearchUsers)).Methods("GET")
}