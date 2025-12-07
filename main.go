package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
)

// --- Config ---
var (
	DB_DSN    string
	HTTP_PORT string
)

// --- Initialization ---
func init() {
	_ = godotenv.Load()
	DB_DSN = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		getEnv("DB_USER", "root"),
		getEnv("DB_PASS", "password"),
		getEnv("DB_HOST", "127.0.0.1"),
		getEnv("DB_PORT", "3306"),
		getEnv("DB_NAME", "network_monitor"))
	HTTP_PORT = getEnv("HTTP_PORT", ":8080")

	// Generate RSA Keys on startup
	var err error
	PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("Failed to generate RSA keys:", err)
	}
	pubASN1, err := x509.MarshalPKIXPublicKey(&PrivateKey.PublicKey)
	if err != nil {
		log.Fatal("Failed to marshal public key:", err)
	}
	PublicKey = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// --- Main ---
func main() {
	var err error
	db, err = sql.Open("mysql", DB_DSN)
	if err != nil {
		log.Fatal("DB Driver Error:", err)
	}
	if err = db.Ping(); err != nil {
		log.Fatal("DB Connection Error:", err)
	}

	go startTrapReceiver()
	go startDynamicPoller()
	go cleanExpiredSessions()

	// Public
	http.HandleFunc("/api/auth/key", handlePublicKey)
	http.HandleFunc("/api/login", handleLogin)

	// Protected
	http.Handle("/api/auth/me", authMiddleware(http.HandlerFunc(handleMe)))
	http.Handle("/api/devices", authMiddleware(http.HandlerFunc(handleDevices)))
	http.Handle("/api/device/action", authMiddleware(http.HandlerFunc(handleDeviceAction)))
	http.Handle("/api/device/detail", authMiddleware(http.HandlerFunc(handleDetail)))
	http.Handle("/api/alerts", authMiddleware(http.HandlerFunc(handleAlerts)))

	// Admin
	http.Handle("/api/logs", adminMiddleware(http.HandlerFunc(handleLogs)))
	http.Handle("/api/settings", adminMiddleware(http.HandlerFunc(handleSettings)))
	http.Handle("/api/scan", adminMiddleware(http.HandlerFunc(handleScan)))
	http.Handle("/api/admin/users", adminMiddleware(http.HandlerFunc(handleUsers)))
	http.Handle("/api/admin/permissions", adminMiddleware(http.HandlerFunc(handlePermissions)))

	dbLog("INFO", "System", "Server started on "+HTTP_PORT)
	log.Println("Listening on " + HTTP_PORT)
	log.Fatal(http.ListenAndServe(HTTP_PORT, nil))
}
