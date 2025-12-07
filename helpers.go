package main

import (
	"log"
	"net"
	"net/http"
	"strconv"
)

// dbLog logs messages to the console and the database
func dbLog(level, source, msg string) {
	log.Printf("[%s] %s: %s", level, source, msg)
	// Run in goroutine to not block main flow
	go func() {
		if db != nil {
			db.Exec("INSERT INTO system_logs (level, source, message) VALUES (?,?,?)", level, source, msg)
		}
	}()
}

// getSettingInt fetches a setting from the DB or returns a default
func getSettingInt(key string, def int) int {
	if db == nil {
		return def
	}
	var val string
	if err := db.QueryRow("SELECT value_str FROM settings WHERE key_name=?", key).Scan(&val); err != nil {
		return def
	}
	i, _ := strconv.Atoi(val)
	return i
}

// createAlert logs an alert to the database
func createAlert(devId int, severity, msg string) {
	if db == nil {
		return
	}
	var count int
	db.QueryRow("SELECT COUNT(*) FROM alerts WHERE device_id=? AND message=? AND is_active=1", devId, msg).Scan(&count)
	if count == 0 {
		db.Exec("INSERT INTO alerts (device_id, severity, message) VALUES (?,?,?)", devId, severity, msg)
	}
}

// incIP increments an IP address
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// enableCors sets standard CORS headers
func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}
