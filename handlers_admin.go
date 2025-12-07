package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

func handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		rows, _ := db.Query("SELECT id, username, role, email, created_at FROM users")
		defer rows.Close()
		var users []map[string]interface{}
		for rows.Next() {
			var u struct {
				ID                         int
				User, Role, Email, Created string
			}
			rows.Scan(&u.ID, &u.User, &u.Role, &u.Email, &u.Created)
			users = append(users, map[string]interface{}{
				"id": u.ID, "username": u.User, "role": u.Role, "email": u.Email, "created_at": u.Created,
			})
		}
		json.NewEncoder(w).Encode(users)
	} else if r.Method == "POST" {
		var req struct{ Username, Password, Role, Email string }
		json.NewDecoder(r.Body).Decode(&req)

		hash := sha256.Sum256([]byte(req.Password))
		passHash := hex.EncodeToString(hash[:])

		_, err := db.Exec("INSERT INTO users (username, password_hash, role, email) VALUES (?,?,?,?)", req.Username, passHash, req.Role, req.Email)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(201)
	} else if r.Method == "PUT" {
		var req struct {
			ID                              int `json:"id"`
			Username, Password, Role, Email string
		}
		json.NewDecoder(r.Body).Decode(&req)

		if req.Password != "" {
			hash := sha256.Sum256([]byte(req.Password))
			passHash := hex.EncodeToString(hash[:])
			_, err := db.Exec("UPDATE users SET username=?, role=?, email=?, password_hash=? WHERE id=?", req.Username, req.Role, req.Email, passHash, req.ID)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
		} else {
			_, err := db.Exec("UPDATE users SET username=?, role=?, email=? WHERE id=?", req.Username, req.Role, req.Email, req.ID)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
		}
		w.WriteHeader(200)
	} else if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		db.Exec("DELETE FROM users WHERE id=?", id)
		w.WriteHeader(200)
	}
}

func handlePermissions(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		userId := r.URL.Query().Get("user_id")
		rows, _ := db.Query(`
			SELECT d.id, d.hostname, p.can_write 
			FROM devices d 
			LEFT JOIN user_device_permissions p ON d.id = p.device_id AND p.user_id = ?
		`, userId)
		defer rows.Close()
		var perms []map[string]interface{}
		for rows.Next() {
			var dID int
			var host string
			var write sql.NullBool
			rows.Scan(&dID, &host, &write)
			perms = append(perms, map[string]interface{}{
				"device_id": dID, "hostname": host, "has_access": write.Valid, "can_write": write.Valid && write.Bool,
			})
		}
		json.NewEncoder(w).Encode(perms)
	} else if r.Method == "POST" {
		var req struct {
			UserId, DeviceId    int
			HasAccess, CanWrite bool
		}
		json.NewDecoder(r.Body).Decode(&req)
		if !req.HasAccess {
			db.Exec("DELETE FROM user_device_permissions WHERE user_id=? AND device_id=?", req.UserId, req.DeviceId)
		} else {
			db.Exec(`INSERT INTO user_device_permissions (user_id, device_id, can_write) VALUES (?,?,?) 
				ON DUPLICATE KEY UPDATE can_write=?`, req.UserId, req.DeviceId, req.CanWrite, req.CanWrite)
		}
		w.WriteHeader(200)
	}
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.Query("SELECT level, source, message, created_at FROM system_logs ORDER BY created_at DESC LIMIT 100")
	defer rows.Close()
	var res []map[string]interface{}
	for rows.Next() {
		var l, s, m string
		var t time.Time
		rows.Scan(&l, &s, &m, &t)
		res = append(res, map[string]interface{}{"level": l, "source": s, "message": m, "time": t.Format("2006-01-02 15:04:05")})
	}
	if res == nil {
		res = []map[string]interface{}{}
	}
	json.NewEncoder(w).Encode(res)
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var settings map[string]interface{}
		json.NewDecoder(r.Body).Decode(&settings)
		for k, v := range settings {
			strVal := fmt.Sprintf("%v", v)
			db.Exec("INSERT INTO settings (key_name, value_str) VALUES (?,?) ON DUPLICATE KEY UPDATE value_str=?", k, strVal, strVal)
		}
		dbLog("INFO", "API", "Settings updated by admin")
		return
	}
	rows, _ := db.Query("SELECT key_name, value_str FROM settings")
	defer rows.Close()
	res := make(map[string]string)
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		res[k] = v
	}
	json.NewEncoder(w).Encode(res)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	var req struct {
		Cidr      string `json:"cidr"`
		Community string `json:"community"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Community == "" {
		req.Community = "public"
	}

	ip, ipnet, err := net.ParseCIDR(req.Cidr)
	if err != nil {
		http.Error(w, "Invalid CIDR", 400)
		return
	}

	foundHosts := []map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		targetIP := ip.String()
		if strings.HasSuffix(targetIP, ".0") || strings.HasSuffix(targetIP, ".255") {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }()

			snmp := &gosnmp.GoSNMP{
				Target: ipStr, Port: 161, Community: req.Community, Version: gosnmp.Version2c,
				Timeout: 1 * time.Second, Retries: 0,
			}
			if err := snmp.Connect(); err == nil {
				defer snmp.Conn.Close()
				res, err := snmp.Get([]string{OID_SYS_NAME})
				if err == nil && len(res.Variables) > 0 {
					name := "Unknown"
					if len(res.Variables) > 0 && res.Variables[0].Type == gosnmp.OctetString {
						name = string(res.Variables[0].Value.([]byte))
					}
					mu.Lock()
					foundHosts = append(foundHosts, map[string]string{"ip": ipStr, "hostname": name})
					mu.Unlock()
				}
			}
		}(targetIP)
	}
	wg.Wait()
	json.NewEncoder(w).Encode(foundHosts)
}
