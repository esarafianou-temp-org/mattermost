// SAST EVALUATION FILE - CWE-352 (Cross-Site Request Forgery)
// WARNING: This file contains intentional security vulnerabilities for SAST tool evaluation
// DO NOT MERGE - This code is unsafe and should never be used in production

package api4

import (
	"encoding/json"
	"net/http"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/v8/channels/web"
)

/**
 * SECURITY VULNERABILITY - CWE-352: Cross-Site Request Forgery (CSRF)
 * 
 * This endpoint demonstrates a CSRF vulnerability by accepting state-changing
 * operations via GET requests and not validating CSRF tokens. This allows
 * malicious websites to perform actions on behalf of authenticated users.
 * 
 * Attack Scenario:
 * 1. User is logged into Mattermost in one browser tab
 * 2. User visits malicious website in another tab
 * 3. Malicious website includes: <img src="https://mattermost.com/api/v4/sast-eval/admin/delete-user?user_id=victim">
 * 4. Browser automatically sends request with user's authentication cookies
 * 5. User account gets deleted without user's knowledge or consent
 * 
 * Additional attack vectors:
 * - Hidden forms with auto-submit JavaScript
 * - XMLHttpRequest from malicious sites (if CORS is misconfigured)
 * - Social engineering links in emails/messages
 * 
 * VULNERABILITY: No CSRF protection on state-changing operations
 * FIX: Implement CSRF tokens, use POST/PUT/DELETE methods, validate Origin/Referer headers
 */
func sastEvalDeleteUser(c *Context, w http.ResponseWriter, r *http.Request) {
	// Extract user ID from query parameter - dangerous for GET request
	userIdToDelete := r.URL.Query().Get("user_id")

	if userIdToDelete == "" {
		c.Err = model.NewAppError("sastEvalDeleteUser", "api.user.delete.missing_user_id", nil, "", http.StatusBadRequest)
		return
	}

	// VULNERABLE: No CSRF token validation
	// VULNERABLE: State-changing operation via GET request
	// VULNERABLE: No additional confirmation required for destructive action

	// Get the current user (from session/token)
	if c.AppContext.Session().UserId == "" {
		c.Err = model.NewAppError("sastEvalDeleteUser", "api.user.delete.unauthorized", nil, "", http.StatusUnauthorized)
		return
	}

	// VULNERABLE: Performing destructive action without CSRF protection
	// This would normally delete the user from the database
	// For evaluation purposes, we'll simulate the action
	
	// Simulate user deletion (don't actually delete in evaluation code)
	c.Logger.Warn("SAST EVAL: Simulated user deletion", 
		map[string]interface{}{
			"deleted_user_id": userIdToDelete,
			"actor_user_id": c.AppContext.Session().UserId,
			"method": r.Method,
			"csrf_token": r.Header.Get("X-CSRF-Token"), // This will be empty, showing the vulnerability
		})

	// Return success response (in real attack, user would be deleted)
	response := map[string]interface{}{
		"success": true,
		"message": "User deleted successfully",
		"deleted_user_id": userIdToDelete,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

/**
 * Additional CSRF vulnerability - Password change via GET
 * Even more dangerous as it can lead to account takeover
 */
func sastEvalChangePassword(c *Context, w http.ResponseWriter, r *http.Request) {
	newPassword := r.URL.Query().Get("new_password")
	userId := c.AppContext.Session().UserId

	if userId == "" {
		c.Err = model.NewAppError("sastEvalChangePassword", "api.user.password.unauthorized", nil, "", http.StatusUnauthorized)
		return
	}

	if newPassword == "" {
		c.Err = model.NewAppError("sastEvalChangePassword", "api.user.password.missing_password", nil, "", http.StatusBadRequest)
		return
	}

	// VULNERABLE: Password change via GET request with no CSRF protection
	// Attack: <img src="https://mattermost.com/api/v4/sast-eval/change-password?new_password=hacked123">
	
	c.Logger.Warn("SAST EVAL: Simulated password change",
		map[string]interface{}{
			"user_id": userId,
			"method": r.Method,
			"new_password_length": len(newPassword),
		})

	response := map[string]interface{}{
		"success": true,
		"message": "Password changed successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

/**
 * CSRF vulnerability in POST request (less obvious but still vulnerable)
 * Shows that even POST requests can be CSRF vulnerable without proper token validation
 */
func sastEvalPromoteToAdmin(c *Context, w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		UserID string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		c.Err = model.NewAppError("sastEvalPromoteToAdmin", "api.user.promote.invalid_json", nil, err.Error(), http.StatusBadRequest)
		return
	}

	if c.AppContext.Session().UserId == "" {
		c.Err = model.NewAppError("sastEvalPromoteToAdmin", "api.user.promote.unauthorized", nil, "", http.StatusUnauthorized)
		return
	}

	// VULNERABLE: No CSRF token validation even on POST request
	// Attack via malicious form:
	// <form action="https://mattermost.com/api/v4/sast-eval/promote-admin" method="POST">
	//   <input type="hidden" name="user_id" value="attacker_id">
	// </form>
	// <script>document.forms[0].submit();</script>

	c.Logger.Warn("SAST EVAL: Simulated admin promotion",
		map[string]interface{}{
			"promoted_user_id": requestBody.UserID,
			"actor_user_id": c.AppContext.Session().UserId,
			"csrf_token": r.Header.Get("X-CSRF-Token"), // Still empty - showing vulnerability
		})

	response := map[string]interface{}{
		"success": true,
		"message": "User promoted to admin",
		"user_id": requestBody.UserID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Example of secure implementation (commented out):
// func secureDeleteUser(c *Context, w http.ResponseWriter, r *http.Request) {
//     // SECURE: Only accept POST/DELETE methods for state changes
//     if r.Method != http.MethodDelete {
//         c.Err = model.NewAppError("deleteUser", "api.user.delete.method_not_allowed", nil, "", http.StatusMethodNotAllowed)
//         return
//     }
//
//     // SECURE: Validate CSRF token
//     csrfToken := r.Header.Get("X-CSRF-Token")
//     if !c.App.VerifyCSRFToken(csrfToken, c.AppContext.Session().Token) {
//         c.Err = model.NewAppError("deleteUser", "api.user.delete.csrf_invalid", nil, "", http.StatusForbidden)
//         return
//     }
//
//     // SECURE: Additional confirmation required for destructive actions
//     if r.Header.Get("X-Confirm-Action") != "DELETE_USER" {
//         c.Err = model.NewAppError("deleteUser", "api.user.delete.confirmation_required", nil, "", http.StatusBadRequest)
//         return
//     }
//
//     // ... rest of secure implementation
// }

func init() {
	// Register the vulnerable endpoints - these should never be merged
	// BaseRoutes.ApiRoot.Handle("/sast-eval/admin/delete-user", ApiHandler(sastEvalDeleteUser)).Methods("GET")
	// BaseRoutes.ApiRoot.Handle("/sast-eval/change-password", ApiHandler(sastEvalChangePassword)).Methods("GET") 
	// BaseRoutes.ApiRoot.Handle("/sast-eval/promote-admin", ApiHandler(sastEvalPromoteToAdmin)).Methods("POST")
}