package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

// --- Middleware ---

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if r.Method == "OPTIONS" {
			return
		}
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", 401)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		var user User
		err := db.QueryRow(`SELECT u.id, u.username, u.role, u.email FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ? AND s.expires_at > NOW()`, token).Scan(&user.ID, &user.Username, &user.Role, &user.Email)
		if err != nil {
			http.Error(w, "Invalid Token", 401)
			return
		}
		ctx := context.WithValue(r.Context(), UserKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func adminMiddleware(next http.Handler) http.Handler {
	return authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value(UserKey).(User)
		if user.Role != "admin" {
			http.Error(w, "Forbidden", 403)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// --- Handlers ---

func handlePublicKey(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "GET" {
		json.NewEncoder(w).Encode(map[string]string{"publicKey": string(PublicKey)})
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", 400)
		return
	}

	// 1. Decode Base64
	cipherText, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil {
		http.Error(w, "Invalid Encoding", 400)
		return
	}

	// 2. Decrypt with Private Key
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, PrivateKey, cipherText)
	if err != nil {
		log.Println("Decryption failed:", err)
		http.Error(w, "Decryption Failed", 400)
		return
	}

	// 3. Parse Inner JSON
	var creds struct {
		Username string
		Password string
	}
	if err := json.Unmarshal(plainText, &creds); err != nil {
		http.Error(w, "Invalid Credential Format", 400)
		return
	}

	// 4. Validate DB
	hash := sha256.Sum256([]byte(creds.Password))
	passHash := hex.EncodeToString(hash[:])

	var user User
	err = db.QueryRow("SELECT id, username, role, email FROM users WHERE username=? AND password_hash=?", creds.Username, passHash).Scan(&user.ID, &user.Username, &user.Role, &user.Email)
	if err != nil {
		http.Error(w, "Invalid credentials", 401)
		return
	}

	// 5. Session
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)
	db.Exec("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 24 HOUR))", token, user.ID)

	json.NewEncoder(w).Encode(map[string]interface{}{"token": token, "user": user})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(UserKey).(User)
	json.NewEncoder(w).Encode(user)
}

func cleanExpiredSessions() {
	for {
		db.Exec("DELETE FROM sessions WHERE expires_at < NOW()")
		time.Sleep(1 * time.Hour)
	}
}
