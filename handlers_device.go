package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func handleDevices(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(UserKey).(User)
	var sqlStr string
	var args []interface{}

	if user.Role == "admin" {
		sqlStr = "SELECT id, hostname, ip_address, community_string, COALESCE(sys_descr,''), COALESCE(sys_location,''), is_paused, COALESCE(status, 'unknown') FROM devices"
	} else {
		sqlStr = `SELECT d.id, d.hostname, d.ip_address, d.community_string, COALESCE(d.sys_descr,''), COALESCE(d.sys_location,''), d.is_paused, COALESCE(d.status, 'unknown') 
				  FROM devices d JOIN user_device_permissions p ON d.id = p.device_id WHERE p.user_id = ?`
		args = append(args, user.ID)
	}

	query := r.URL.Query().Get("q")
	if query != "" {
		sqlStr += " WHERE (hostname LIKE ? OR ip_address LIKE ?)"
		if user.Role != "admin" {
			sqlStr = strings.Replace(sqlStr, "WHERE", "AND", 1)
		}
		args = append(args, "%"+query+"%", "%"+query+"%")
	}

	if r.Method == "POST" || r.Method == "PUT" {
		handleDeviceCreateUpdate(w, r, user)
		return
	}

	rows, err := db.Query(sqlStr, args...)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var res []map[string]interface{}
	for rows.Next() {
		var id int
		var h, ip, comm, desc, loc, status string
		var p bool
		rows.Scan(&id, &h, &ip, &comm, &desc, &loc, &p, &status)

		canWrite := false
		if user.Role == "admin" {
			canWrite = true
		} else {
			db.QueryRow("SELECT can_write FROM user_device_permissions WHERE user_id=? AND device_id=?", user.ID, id).Scan(&canWrite)
		}
		res = append(res, map[string]interface{}{
			"id": id, "hostname": h, "ip": ip, "community": comm, "description": desc, "location": loc, "is_paused": p, "status": status, "can_write": canWrite,
		})
	}
	if res == nil {
		res = []map[string]interface{}{}
	}
	json.NewEncoder(w).Encode(res)
}

func handleDeviceCreateUpdate(w http.ResponseWriter, r *http.Request, user User) {
	if r.Method == "POST" {
		if user.Role != "admin" {
			http.Error(w, "Forbidden", 403)
			return
		}
		var d struct {
			Hostname, Ip, Community string
			Force                   bool
		}
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			http.Error(w, "Invalid JSON", 400)
			return
		}
		if d.Community == "" {
			d.Community = "public"
		}

		var existingId int
		var existingHost string
		err := db.QueryRow("SELECT id, hostname FROM devices WHERE ip_address=?", d.Ip).Scan(&existingId, &existingHost)
		if err == nil {
			if !d.Force {
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "Duplicate IP", "existing_hostname": existingHost, "existing_id": existingId})
				return
			} else {
				db.Exec("UPDATE devices SET hostname=?, community_string=?, is_paused=0, status='unknown' WHERE id=?", d.Hostname, d.Community, existingId)
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		db.Exec("INSERT INTO devices (hostname, ip_address, community_string, status) VALUES (?,?,?, 'unknown')", d.Hostname, d.Ip, d.Community)
		w.WriteHeader(http.StatusCreated)
	} else if r.Method == "PUT" {
		var d struct {
			Id                      int
			Hostname, Ip, Community string
		}
		json.NewDecoder(r.Body).Decode(&d)
		if user.Role != "admin" {
			var canWrite bool
			err := db.QueryRow("SELECT can_write FROM user_device_permissions WHERE user_id=? AND device_id=?", user.ID, d.Id).Scan(&canWrite)
			if err != nil || !canWrite {
				http.Error(w, "Forbidden", 403)
				return
			}
		}
		db.Exec("UPDATE devices SET hostname=?, ip_address=?, community_string=? WHERE id=?", d.Hostname, d.Ip, d.Community, d.Id)
		w.WriteHeader(http.StatusOK)
	}
}

func handleDeviceAction(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		return
	}
	user := r.Context().Value(UserKey).(User)
	var req struct {
		Action string
		Id     int
	}
	json.NewDecoder(r.Body).Decode(&req)

	if user.Role != "admin" {
		var canWrite bool
		err := db.QueryRow("SELECT can_write FROM user_device_permissions WHERE user_id=? AND device_id=?", user.ID, req.Id).Scan(&canWrite)
		if err != nil || !canWrite {
			http.Error(w, "Forbidden", 403)
			return
		}
	}

	if req.Action == "delete" {
		db.Exec("DELETE FROM devices WHERE id=?", req.Id)
	} else if req.Action == "pause" {
		db.Exec("UPDATE devices SET is_paused=1 WHERE id=?", req.Id)
	} else if req.Action == "resume" {
		db.Exec("UPDATE devices SET is_paused=0 WHERE id=?", req.Id)
	}
}

func handleDetail(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(UserKey).(User)
	idStr := r.URL.Query().Get("id")
	id, _ := strconv.Atoi(idStr)

	if user.Role != "admin" {
		var exists int
		if err := db.QueryRow("SELECT 1 FROM user_device_permissions WHERE user_id=? AND device_id=?", user.ID, id).Scan(&exists); err != nil {
			http.Error(w, "Forbidden", 403)
			return
		}
	}

	// History
	hRows, _ := db.Query(`SELECT load_1min, load_5min, load_15min, ram_used, ram_total, swap_used, swap_total, collected_at FROM device_health WHERE device_id=? ORDER BY collected_at DESC LIMIT 30`, id)
	defer hRows.Close()
	var history []map[string]interface{}
	var curRam, curSwap int64
	for hRows.Next() {
		var l1, l5, l15 float64
		var ram, ramTot, swap, swapTot int64
		var t time.Time
		hRows.Scan(&l1, &l5, &l15, &ram, &ramTot, &swap, &swapTot, &t)
		curRam, curSwap = ramTot, swapTot
		history = append(history, map[string]interface{}{"time": t.Format("15:04"), "load1": l1, "load5": l5, "load15": l15, "ram_used": ram / 1024 / 1024, "swap_used": swap / 1024 / 1024})
	}
	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}

	// Net
	nRows, _ := db.Query(`SELECT collected_at, SUM(hc_in_octets), SUM(hc_out_octets), SUM(in_errors + out_errors) FROM interface_metrics WHERE device_id=? GROUP BY collected_at ORDER BY collected_at DESC LIMIT 30`, id)
	defer nRows.Close()
	var netHistory []map[string]interface{}
	for nRows.Next() {
		var t time.Time
		var in, out, errs int64
		nRows.Scan(&t, &in, &out, &errs)
		netHistory = append(netHistory, map[string]interface{}{"time": t.Format("15:04"), "rx_kb": in / 1024, "tx_kb": out / 1024, "errors": errs})
	}
	for i, j := 0, len(netHistory)-1; i < j; i, j = i+1, j-1 {
		netHistory[i], netHistory[j] = netHistory[j], netHistory[i]
	}

	// Info
	var sys struct{ Descr, Contact, Location string }
	var uptime int64
	db.QueryRow("SELECT COALESCE(sys_descr,''), COALESCE(sys_contact,''), COALESCE(sys_location,'') FROM devices WHERE id=?", id).Scan(&sys.Descr, &sys.Contact, &sys.Location)
	db.QueryRow("SELECT uptime_seconds FROM device_health WHERE device_id=? ORDER BY collected_at DESC LIMIT 1", id).Scan(&uptime)

	// Interfaces
	iRows, _ := db.Query(`SELECT interface_name, alias, oper_status, speed_high, hc_in_octets, hc_out_octets, in_ucast_pkts, in_mcast_pkts, in_bcast_pkts, in_errors, out_errors, in_discards, out_discards FROM interface_metrics WHERE device_id=? AND collected_at = (SELECT MAX(collected_at) FROM interface_metrics WHERE device_id=?)`, id, id)
	defer iRows.Close()
	var ifaces []map[string]interface{}
	for iRows.Next() {
		var name, alias string
		var status int
		var speed, in, out, ucast, mcast, bcast, inErr, outErr, inDisc, outDisc int64
		iRows.Scan(&name, &alias, &status, &speed, &in, &out, &ucast, &mcast, &bcast, &inErr, &outErr, &inDisc, &outDisc)
		ifaces = append(ifaces, map[string]interface{}{"name": name, "alias": alias, "status": status, "speed": speed, "in_bytes": in, "out_bytes": out, "errors": inErr + outErr, "discards": inDisc + outDisc})
	}

	// Storage
	sRows, _ := db.Query(`SELECT storage_descr, size_bytes, used_bytes FROM storage_metrics WHERE device_id=? AND collected_at = (SELECT MAX(collected_at) FROM storage_metrics WHERE device_id=?)`, id, id)
	defer sRows.Close()
	var storage []map[string]interface{}
	for sRows.Next() {
		var d string
		var s, u int64
		sRows.Scan(&d, &s, &u)
		storage = append(storage, map[string]interface{}{"name": d, "size": s, "used": u})
	}

	// Proto
	var tcpEstab, tcpIn, tcpOut, udpIn, udpOut, icmpIn, icmpOut int64
	db.QueryRow(`SELECT tcp_curr_estab, tcp_in_segs, tcp_out_segs, udp_in_datagrams, udp_out_datagrams, icmp_in_msgs, icmp_out_msgs FROM protocol_metrics WHERE device_id=? ORDER BY collected_at DESC LIMIT 1`, id).Scan(&tcpEstab, &tcpIn, &tcpOut, &udpIn, &udpOut, &icmpIn, &icmpOut)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"sys_info":       map[string]interface{}{"descr": sys.Descr, "contact": sys.Contact, "location": sys.Location, "uptime": uptime, "ram_total": curRam, "swap_total": curSwap},
		"history_health": history, "history_net": netHistory,
		"interfaces":     ifaces, "storage": storage,
		"protocols":      map[string]interface{}{"tcp": map[string]int64{"estab": tcpEstab, "in": tcpIn, "out": tcpOut}, "udp": map[string]int64{"in": udpIn, "out": udpOut}, "icmp": map[string]int64{"in": icmpIn, "out": icmpOut}},
	})
}

func handleAlerts(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(UserKey).(User)
	var rows *sql.Rows
	var err error

	if user.Role == "admin" {
		rows, err = db.Query(`SELECT a.id, a.severity, a.message, a.created_at, d.hostname 
			FROM alerts a JOIN devices d ON a.device_id = d.id 
			WHERE a.is_active=1 ORDER BY a.created_at DESC LIMIT 50`)
	} else {
		rows, err = db.Query(`SELECT a.id, a.severity, a.message, a.created_at, d.hostname 
			FROM alerts a 
			JOIN devices d ON a.device_id = d.id 
			JOIN user_device_permissions p ON d.id = p.device_id
			WHERE a.is_active=1 AND p.user_id = ? 
			ORDER BY a.created_at DESC LIMIT 50`, user.ID)
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var res []map[string]interface{}
	for rows.Next() {
		var id int
		var sev, msg, host string
		var t time.Time
		rows.Scan(&id, &sev, &msg, &t, &host)
		res = append(res, map[string]interface{}{"id": id, "severity": sev, "message": msg, "time": t.Format("15:04:05"), "hostname": host})
	}
	if res == nil {
		res = []map[string]interface{}{}
	}
	json.NewEncoder(w).Encode(res)
}
