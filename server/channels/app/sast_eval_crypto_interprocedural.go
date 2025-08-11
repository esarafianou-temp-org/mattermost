// SAST EVALUATION FILE - Interprocedural Cryptographic Analysis Challenges
// WARNING: This file contains intentional security vulnerabilities for SAST tool evaluation
// DO NOT MERGE - This code is unsafe and should never be used in production

package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

/**
 * INTERPROCEDURAL ANALYSIS CHALLENGES - Item 2 from SAST notes
 * 
 * These examples test whether SAST tools can follow data flow across
 * function boundaries to understand cryptographic context and security.
 * 
 * Challenge: Understanding encryption vs decryption context and IV generation
 * across multiple functions and call sites.
 */

// This looks like a secure IV generation function
func generateSecureIV() ([]byte, error) {
	// CORRECT: Using crypto/rand for IV generation
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	return iv, err
}

// This generates a WEAK IV (predictable)
func generateWeakIV(userID string, timestamp int64) []byte {
	// VULNERABLE: Predictable IV generation
	// IV should be random, not based on predictable inputs
	iv := make([]byte, aes.BlockSize)
	seed := fmt.Sprintf("%s_%d", userID, timestamp)
	for i := 0; i < len(iv) && i < len(seed); i++ {
		iv[i] = byte(seed[i])
	}
	return iv
}

// Encryption function that accepts IV as parameter
// SAST tools need to track where IV comes from to determine security
func encryptDataAES(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	if len(key) != 32 { // AES-256
		return nil, errors.New("invalid key length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV parameter could be secure or insecure depending on caller
	// SAST tools need interprocedural analysis to determine this
	mode := cipher.NewCBCEncrypter(block, iv)
	
	// Add padding (simplified for example)
	paddedData := padPKCS7(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(paddedData))
	mode.CryptBlocks(ciphertext, paddedData)
	
	return ciphertext, nil
}

// Decryption function - uses IV from ciphertext (correct)
func decryptDataAES(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// CONTEXT: For decryption, using stored/transmitted IV is CORRECT
	// SAST tools should understand this is different from encryption context
	mode := cipher.NewCBCDecrypter(block, iv)
	
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	
	return removePKCS7Padding(plaintext), nil
}

/**
 * SECURE USAGE: Proper IV generation for encryption
 * SAST tools should recognize this as secure
 */
func encryptUserDataSecurely(userData []byte, encryptionKey []byte) ([]byte, []byte, error) {
	// SECURE: Generate random IV for encryption
	iv, err := generateSecureIV()
	if err != nil {
		return nil, nil, err
	}
	
	ciphertext, err := encryptDataAES(userData, encryptionKey, iv)
	if err != nil {
		return nil, nil, err
	}
	
	// Return both ciphertext and IV (IV can be stored/transmitted in plaintext)
	return ciphertext, iv, nil
}

/**
 * VULNERABLE USAGE: Predictable IV generation
 * SAST tools need to trace the IV source through multiple function calls
 */
func encryptUserDataVulnerable(userData []byte, encryptionKey []byte, userID string) ([]byte, []byte, error) {
	// VULNERABLE: Using predictable IV generation
	timestamp := time.Now().Unix()
	iv := generateWeakIV(userID, timestamp)
	
	// SAST tools need to recognize that even though encryptDataAES is the same,
	// the IV source makes this usage vulnerable
	ciphertext, err := encryptDataAES(userData, encryptionKey, iv)
	if err != nil {
		return nil, nil, err
	}
	
	return ciphertext, iv, nil
}

/**
 * CORRECT USAGE: Using stored IV for decryption
 * This should NOT be flagged as vulnerable by SAST tools
 */
func decryptUserDataCorrectly(ciphertext []byte, storedIV []byte, decryptionKey []byte) ([]byte, error) {
	// CORRECT: Using previously generated/stored IV for decryption
	// Even if the IV was generated predictably during encryption,
	// using it for decryption is the correct approach
	return decryptDataAES(ciphertext, decryptionKey, storedIV)
}

/**
 * CONSTANT IV VULNERABILITY: Most dangerous case
 * Using same IV for multiple encryptions with same key
 */
const CONSTANT_IV = "1234567890123456" // 16 bytes for AES

func encryptWithConstantIV(plaintext []byte, key []byte) ([]byte, error) {
	// VERY VULNERABLE: Constant IV allows pattern analysis
	// Same plaintext will always produce same ciphertext
	iv := []byte(CONSTANT_IV)
	return encryptDataAES(plaintext, key, iv)
}

/**
 * MIXED CONTEXT EXAMPLE: Tests SAST tool's ability to differentiate contexts
 * Same IV handling code used in both secure and insecure ways
 */
type CryptoManager struct {
	masterKey []byte
}

func (cm *CryptoManager) processDataEncryption(data []byte, operationType string) ([]byte, []byte, error) {
	switch operationType {
	case "secure_encrypt":
		// SECURE: Random IV for new encryption
		return encryptUserDataSecurely(data, cm.masterKey)
		
	case "vulnerable_encrypt":
		// VULNERABLE: Predictable IV
		userID := "user123" // Simulated
		return encryptUserDataVulnerable(data, cm.masterKey, userID)
		
	case "constant_iv_encrypt":
		// VERY VULNERABLE: Constant IV
		iv := []byte(CONSTANT_IV)
		ciphertext, err := encryptDataAES(data, cm.masterKey, iv)
		return ciphertext, iv, err
		
	default:
		return nil, nil, errors.New("unknown operation")
	}
}

// Helper functions
func padPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

func removePKCS7Padding(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding > len(data) {
		return data
	}
	return data[:len(data)-padding]
}

// Example of what secure implementation should look like (commented out):
// func encryptSecurelyWithGCM(plaintext []byte, key []byte) ([]byte, []byte, error) {
//     // SECURE: Use AES-GCM which handles IV/nonce automatically
//     block, err := aes.NewCipher(key)
//     if err != nil {
//         return nil, nil, err
//     }
//
//     gcm, err := cipher.NewGCM(block)
//     if err != nil {
//         return nil, nil, err
//     }
//
//     // Generate random nonce
//     nonce := make([]byte, gcm.NonceSize())
//     if _, err := rand.Read(nonce); err != nil {
//         return nil, nil, err
//     }
//
//     // GCM provides both encryption and authentication
//     ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
//     return ciphertext, nonce, nil
// }