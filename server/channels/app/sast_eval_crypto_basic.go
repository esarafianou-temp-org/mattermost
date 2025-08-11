// SAST EVALUATION FILE - Cryptographic Vulnerabilities - Basic Examples
// WARNING: This file contains intentional security vulnerabilities for SAST tool evaluation
// DO NOT MERGE - This code is unsafe and should never be used in production

package app

import (
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
)

/**
 * CRYPTOGRAPHIC VULNERABILITY - Weak Hash Functions
 * 
 * These examples use cryptographically weak hash functions that are
 * easily broken and should not be used for security purposes.
 * 
 * SAST tools should easily detect these as they are well-known weak algorithms.
 */

// VULNERABLE: Using MD5 for password hashing
// MD5 is cryptographically broken and vulnerable to collision attacks
func hashPasswordMD5(password string) string {
	// SECURITY FLAW: MD5 is not suitable for password hashing
	hasher := md5.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

// VULNERABLE: Using SHA-1 for digital signatures
// SHA-1 is deprecated and vulnerable to collision attacks since 2017
func generateTokenSHA1(data string) string {
	// SECURITY FLAW: SHA-1 should not be used for security-critical operations
	hasher := sha1.New()
	hasher.Write([]byte(data))
	return hex.EncodeToString(hasher.Sum(nil))
}

// VULNERABLE: Using DES encryption
// DES has a 56-bit key which is easily brute-forced
func encryptWithDES(plaintext []byte, key []byte) ([]byte, error) {
	// SECURITY FLAW: DES is obsolete and easily broken
	// Key length is only 56 bits effective (64 bits with parity)
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// This is just for demonstration - don't actually implement DES encryption
	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, plaintext)
	return ciphertext, nil
}

/**
 * VULNERABLE: Multiple weak algorithms in authentication system
 * This simulates a flawed authentication system using multiple weak cryptographic primitives
 */
func authenticateUserWeakCrypto(username, password, challenge string) (bool, string) {
	// FLAW 1: Hash password with MD5
	passwordHash := hashPasswordMD5(password)
	
	// FLAW 2: Generate challenge response with SHA-1
	challengeResponse := generateTokenSHA1(username + challenge + passwordHash)
	
	// FLAW 3: Use DES key (if we had one) - showing the pattern
	desKey := []byte("weakkey1") // 8 bytes for DES, but still vulnerable
	
	// Simulate authentication logic with weak crypto
	expectedHash := hashPasswordMD5("admin123") // Simulated stored hash
	
	return passwordHash == expectedHash, challengeResponse
}

// Example of what secure implementation should look like (commented out):
// import "golang.org/x/crypto/bcrypt"
// import "crypto/sha256"
// import "crypto/aes"
//
// func hashPasswordSecure(password string) (string, error) {
//     // SECURE: Use bcrypt for password hashing
//     hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
//     return string(hash), err
// }
//
// func generateTokenSecure(data string) string {
//     // SECURE: SHA-256 is acceptable for non-password hashing
//     hasher := sha256.New()
//     hasher.Write([]byte(data))
//     return hex.EncodeToString(hasher.Sum(nil))
// }
//
// func encryptSecure(plaintext []byte, key []byte) ([]byte, error) {
//     // SECURE: Use AES-256 with proper mode
//     block, err := aes.NewCipher(key) // key should be 32 bytes for AES-256
//     // ... proper implementation with GCM or CBC mode
// }