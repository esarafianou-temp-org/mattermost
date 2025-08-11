// SAST EVALUATION FILE - Cryptographic Context Vulnerabilities
// WARNING: This file contains intentional security vulnerabilities for SAST tool evaluation
// DO NOT MERGE - This code is unsafe and should never be used in production

package app

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

/**
 * CRYPTOGRAPHIC CONTEXT VULNERABILITY - Item 1 from SAST notes
 * 
 * These examples demonstrate acceptable cryptographic algorithms used in
 * inappropriate contexts. SAST tools may struggle to identify these as
 * vulnerabilities because the algorithms themselves are not weak.
 * 
 * Challenge: Understanding that context matters for cryptographic security
 */

// VULNERABLE: Using SHA-256 for password hashing
// SHA-256 is a good hash function, but NOT for passwords
// Passwords need slow, memory-hard functions like bcrypt, scrypt, argon2, PBKDF2
func hashUserPasswordSHA256(password string, salt string) string {
	// CONTEXT FLAW: SHA-256 is fast, making it vulnerable to brute force attacks
	// Even with salt, this is still vulnerable because SHA-256 is too fast
	input := password + salt
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

// VULNERABLE: Using SHA-512 for password storage
// SHA-512 is even stronger than SHA-256, but still wrong for passwords
func hashPasswordSHA512WithIterations(password string, salt string, iterations int) string {
	// STILL VULNERABLE: Even with iterations, SHA-512 is not memory-hard
	// GPU-based attacks can still crack these much faster than proper password hashes
	input := []byte(password + salt)
	
	for i := 0; i < iterations; i++ {
		hasher := sha512.New()
		hasher.Write(input)
		input = hasher.Sum(nil)
	}
	
	return hex.EncodeToString(input)
}

// ACCEPTABLE: Using SHA-256 for data integrity (correct context)
func verifyFileIntegrity(fileContent []byte, expectedHash string) bool {
	// CORRECT USAGE: SHA-256 is perfectly fine for file integrity checks
	hasher := sha256.New()
	hasher.Write(fileContent)
	actualHash := hex.EncodeToString(hasher.Sum(nil))
	return actualHash == expectedHash
}

// VULNERABLE: Using secure hash in insecure way for session tokens
func generateSessionTokenSHA256(userId string, timestamp string) string {
	// CONTEXT FLAW: While SHA-256 is secure, this approach is predictable
	// Session tokens should use cryptographically secure random generation
	input := fmt.Sprintf("user_%s_time_%s", userId, timestamp)
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

// VULNERABLE: Password verification that looks secure but isn't
func verifyUserPassword(inputPassword string, storedHash string, salt string) bool {
	// LOOKS SECURE: Using SHA-256 with salt seems reasonable
	// ACTUALLY VULNERABLE: Still too fast for password hashing
	computedHash := hashUserPasswordSHA256(inputPassword, salt)
	return computedHash == storedHash
}

// MIXED CONTEXT: Some correct, some incorrect usage in same system
type AuthenticationSystem struct {
	// This simulates a system where developers correctly use strong algorithms
	// but in wrong contexts, which SAST tools may miss
}

func (auth *AuthenticationSystem) ProcessUserRegistration(username, password, email string) error {
	// CORRECT: Using SHA-256 for email verification token (non-sensitive, temporary)
	emailToken := generateEmailVerificationToken(email)
	
	// WRONG: Using SHA-256 for password (looks similar but different context)
	passwordHash := hashUserPasswordSHA256(password, username) // Using username as salt - also bad
	
	// CORRECT: Using SHA-256 for data integrity
	dataIntegrityHash := computeUserDataHash(username + email)
	
	// Store in database (simulated)
	fmt.Printf("Stored: password_hash=%s, email_token=%s, integrity=%s\n", 
		passwordHash, emailToken, dataIntegrityHash)
	
	return nil
}

func generateEmailVerificationToken(email string) string {
	// ACCEPTABLE: SHA-256 for temporary verification tokens is fine
	hasher := sha256.New()
	hasher.Write([]byte(email + "verification_salt"))
	return hex.EncodeToString(hasher.Sum(nil))
}

func computeUserDataHash(data string) string {
	// ACCEPTABLE: SHA-256 for data integrity checking
	hasher := sha256.New()
	hasher.Write([]byte(data))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Example of what secure password hashing should look like (commented out):
// import "golang.org/x/crypto/bcrypt"
// import "golang.org/x/crypto/scrypt"
//
// func hashPasswordSecurely(password string) (string, error) {
//     // SECURE: Use bcrypt (memory-hard, slow by design)
//     hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
//     return string(hash), err
// }
//
// func hashPasswordWithScrypt(password, salt []byte) ([]byte, error) {
//     // SECURE: Use scrypt (memory-hard function)
//     return scrypt.Key(password, salt, 32768, 8, 1, 32)
// }
//
// func verifyPasswordSecurely(password, hash string) bool {
//     // SECURE: bcrypt handles timing-safe comparison internally
//     err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
//     return err == nil
// }