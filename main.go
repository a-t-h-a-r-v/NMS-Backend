package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gosnmp/gosnmp"
)

// --- Config ---
const (
	DB_DSN    = "atharv:QpMz.1793@tcp(127.0.0.1:3306)/network_monitor?parseTime=true"
	HTTP_PORT = ":8080"
)

// --- OIDs ---
// 1. System Info
const (
	OID_SYS_DESCR    = ".1.3.6.1.2.1.1.1.0"
	OID_SYS_OBJECTID = ".1.3.6.1.2.1.1.2.0"
	OID_SYS_CONTACT  = ".1.3.6.1.2.1.1.4.0"
	OID_SYS_NAME     = ".1.3.6.1.2.1.1.5.0"
	OID_SYS_LOCATION = ".1.3.6.1.2.1.1.6.0"
)

// 2. Interfaces (ifXTable)
const (
	OID_IF_X_ENTRY    = ".1.3.6.1.2.1.31.1.1.1"
	OID_IF_NAME       = ".1"
	OID_IF_IN_MCAST   = ".2"
	OID_IF_IN_BCAST   = ".3"
	OID_IF_OUT_MCAST  = ".4"
	OID_IF_OUT_BCAST  = ".5"
	OID_IF_HC_IN_OCT  = ".6"
	OID_IF_HC_OUT_OCT = ".10"
	OID_IF_HIGH_SPEED = ".15"
	OID_IF_ALIAS      = ".18"
)

// Legacy Interface Table (for Queue len & Discards & Status)
const (
	OID_IF_ENTRY        = ".1.3.6.1.2.1.2.2.1"
	OID_IF_OPER_STATUS  = ".8"
	OID_IF_IN_DISCARDS  = ".13"
	OID_IF_IN_ERRORS    = ".14"
	OID_IF_OUT_DISCARDS = ".19"
	OID_IF_OUT_ERRORS   = ".20"
	OID_IF_OUT_QLEN     = ".21"
)

// 3. CPU/Mem/Swap
const (
	OID_HR_UPTIME      = ".1.3.6.1.2.1.25.1.1.0"
	OID_UCD_LOAD_1     = ".1.3.6.1.4.1.2021.10.1.3.1"
	OID_UCD_LOAD_5     = ".1.3.6.1.4.1.2021.10.1.3.2"
	OID_UCD_LOAD_15    = ".1.3.6.1.4.1.2021.10.1.3.3"
	OID_MEM_TOTAL_REAL = ".1.3.6.1.4.1.2021.4.5.0"
	OID_MEM_AVAIL_REAL = ".1.3.6.1.4.1.2021.4.6.0"
	OID_MEM_TOTAL_SWAP = ".1.3.6.1.4.1.2021.4.3.0"
	OID_MEM_AVAIL_SWAP = ".1.3.6.1.4.1.2021.4.4.0"
)

// 4. Storage
const (
	OID_HR_STORAGE_ENTRY = ".1.3.6.1.2.1.25.2.3.1"
	OID_HR_STOR_DESCR    = ".3"
	OID_HR_STOR_ALLOC    = ".4"
	OID_HR_STOR_SIZE     = ".5"
	OID_HR_STOR_USED     = ".6"
)

// 5. Environment
const (
	OID_LM_TEMP_ENTRY = ".1.3.6.1.4.1.2021.13.16.2.1"
	OID_LM_TEMP_NAME  = ".2"
	OID_LM_TEMP_VAL   = ".3"
)

// 6. Protocols
const (
	OID_TCP_ESTAB      = ".1.3.6.1.2.1.6.9.0"
	OID_TCP_IN_SEGS    = ".1.3.6.1.2.1.6.10.0"
	OID_TCP_OUT_SEGS   = ".1.3.6.1.2.1.6.11.0"
	OID_UDP_IN_DGRAMS  = ".1.3.6.1.2.1.7.1.0"
	OID_UDP_OUT_DGRAMS = ".1.3.6.1.2.1.7.4.0"
	OID_ICMP_IN_MSGS   = ".1.3.6.1.2.1.5.1.0"
	OID_ICMP_OUT_MSGS  = ".1.3.6.1.2.1.5.14.0"
)

var db *sql.DB

// --- Helpers ---

// Log to Database + Console
func dbLog(level, source, msg string) {
	log.Printf("[%s] %s: %s", level, source, msg)
	// We use a goroutine to not block the main flow
	go func() {
		db.Exec("INSERT INTO system_logs (level, source, message) VALUES (?,?,?)", level, source, msg)
	}()
}

// Fetch setting from DB or return default
func getSettingInt(key string, def int) int {
	var val string
	err := db.QueryRow("SELECT value_str FROM settings WHERE key_name=?", key).Scan(&val)
	if err != nil {
		return def
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return def
	}
	return i
}

// Create an alert if it doesn't already exist (deduplication)
func createAlert(devId int, severity, msg string) {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM alerts WHERE device_id=? AND message=? AND is_active=1", devId, msg).Scan(&count)
	if count == 0 {
		db.Exec("INSERT INTO alerts (device_id, severity, message) VALUES (?,?,?)", devId, severity, msg)
		dbLog("WARNING", "AlertEngine", fmt.Sprintf("New Alert for Device %d: %s", devId, msg))
	}
}

// Enable CORS
func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

// --- Main ---

func main() {
	var err error
	db, err = sql.Open("mysql", DB_DSN)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatal("DB Unreachable:", err)
	}

	// Start the Dynamic Poller
	go startDynamicPoller()

	// Handlers
	http.HandleFunc("/api/devices", handleDevices)           // GET (Search), POST (Create)
	http.HandleFunc("/api/device/action", handleDeviceAction) // POST (Delete/Pause)
	http.HandleFunc("/api/device/detail", handleDetail)      // GET (Metrics)
	http.HandleFunc("/api/alerts", handleAlerts)             // GET
	http.HandleFunc("/api/logs", handleLogs)                 // GET
	http.HandleFunc("/api/settings", handleSettings)         // GET, POST

	dbLog("INFO", "System", "Server started on "+HTTP_PORT)
	log.Fatal(http.ListenAndServe(HTTP_PORT, nil))
}

// --- Polling Logic ---

func startDynamicPoller() {
	for {
		// Read interval from DB every cycle (allows changing on the fly)
		interval := getSettingInt("poll_interval", 60)
		dbLog("INFO", "Poller", fmt.Sprintf("Starting poll cycle. Next in %ds", interval))
		
		pollAll()
		
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

func pollAll() {
	// Only fetch unpaused devices
	rows, err := db.Query("SELECT id, hostname, ip_address, community_string FROM devices WHERE is_paused = 0")
	if err != nil {
		dbLog("ERROR", "Poller", "Failed to fetch devices: "+err.Error())
		return
	}
	defer rows.Close()

	var wg sync.WaitGroup
	for rows.Next() {
		var d struct {
			ID             int
			Host, IP, Comm string
		}
		rows.Scan(&d.ID, &d.Host, &d.IP, &d.Comm)
		wg.Add(1)
		go func(id int, host, ip, comm string) {
			defer wg.Done()
			collectDevice(id, host, ip, comm)
		}(d.ID, d.Host, d.IP, d.Comm)
	}
	wg.Wait()
}

func collectDevice(id int, host, ip, comm string) {
	timeout := getSettingInt("snmp_timeout", 2000)
	snmp := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: comm,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(timeout) * time.Millisecond,
		Retries:   1,
	}
	if err := snmp.Connect(); err != nil {
		dbLog("ERROR", "Poller", fmt.Sprintf("[%s] Unreachable: %v", host, err))
		createAlert(id, "critical", "Device Unreachable (Connection Refused/Timeout)")
		return
	}
	defer snmp.Conn.Close()

	// Collect Data
	collectSystemInfo(id, snmp)
	collectHealthAndProtocols(id, snmp) // Includes Alert Logic
	collectInterfaces(id, snmp)         // Includes Alert Logic
	collectStorage(id, snmp)
	collectSensors(id, snmp)
}

func collectSystemInfo(id int, snmp *gosnmp.GoSNMP) {
	oids := []string{OID_SYS_DESCR, OID_SYS_OBJECTID, OID_SYS_CONTACT, OID_SYS_NAME, OID_SYS_LOCATION}
	res, err := snmp.Get(oids)
	if err != nil { return }

	vals := make(map[string]string)
	for _, v := range res.Variables {
		if v.Type == gosnmp.OctetString {
			vals[v.Name] = string(v.Value.([]byte))
		} else if v.Type == gosnmp.ObjectIdentifier {
			vals[v.Name] = v.Value.(string)
		}
	}
	db.Exec(`UPDATE devices SET sys_descr=?, sys_object_id=?, sys_contact=?, sys_name=?, sys_location=? WHERE id=?`,
		vals[OID_SYS_DESCR], vals[OID_SYS_OBJECTID], vals[OID_SYS_CONTACT], vals[OID_SYS_NAME], vals[OID_SYS_LOCATION], id)
}

func collectHealthAndProtocols(id int, snmp *gosnmp.GoSNMP) {
	oids := []string{
		OID_HR_UPTIME, OID_UCD_LOAD_1, OID_UCD_LOAD_5, OID_UCD_LOAD_15,
		OID_MEM_TOTAL_REAL, OID_MEM_AVAIL_REAL, OID_MEM_TOTAL_SWAP, OID_MEM_AVAIL_SWAP,
		OID_TCP_ESTAB, OID_TCP_IN_SEGS, OID_TCP_OUT_SEGS,
		OID_UDP_IN_DGRAMS, OID_UDP_OUT_DGRAMS,
		OID_ICMP_IN_MSGS, OID_ICMP_OUT_MSGS,
	}

	res, err := snmp.Get(oids)
	if err != nil { return }

	v := make(map[string]interface{})
	for _, vb := range res.Variables {
		if vb.Type == gosnmp.OctetString {
			var f float64
			fmt.Sscanf(string(vb.Value.([]byte)), "%f", &f)
			v[vb.Name] = f
		} else {
			v[vb.Name] = gosnmp.ToBigInt(vb.Value).Int64()
		}
	}

	ramTot := v[OID_MEM_TOTAL_REAL].(int64) * 1024
	ramAvail := v[OID_MEM_AVAIL_REAL].(int64) * 1024
	swapTot := v[OID_MEM_TOTAL_SWAP].(int64) * 1024
	swapAvail := v[OID_MEM_AVAIL_SWAP].(int64) * 1024
	uptime := v[OID_HR_UPTIME].(int64) / 100
	load5 := v[OID_UCD_LOAD_5]

	// Insert Health
	db.Exec(`INSERT INTO device_health (device_id, uptime_seconds, load_1min, load_5min, load_15min,
        ram_total, ram_used, swap_total, swap_used) VALUES (?,?,?,?,?,?,?,?,?)`,
		id, uptime, v[OID_UCD_LOAD_1], load5, v[OID_UCD_LOAD_15],
		ramTot, ramTot-ramAvail, swapTot, swapTot-swapAvail)

	// Insert Protocols
	db.Exec(`INSERT INTO protocol_metrics (device_id, tcp_curr_estab, tcp_in_segs, tcp_out_segs,
        udp_in_datagrams, udp_out_datagrams, icmp_in_msgs, icmp_out_msgs) VALUES (?,?,?,?,?,?,?,?)`,
		id, v[OID_TCP_ESTAB], v[OID_TCP_IN_SEGS], v[OID_TCP_OUT_SEGS],
		v[OID_UDP_IN_DGRAMS], v[OID_UDP_OUT_DGRAMS], v[OID_ICMP_IN_MSGS], v[OID_ICMP_OUT_MSGS])

	// --- ALERT CHECK ---
	// If Load > 5.0 (Customize this threshold)
	if l5, ok := load5.(float64); ok && l5 > 5.0 {
		createAlert(id, "warning", fmt.Sprintf("High CPU Load (5min): %.2f", l5))
	}
}

func collectInterfaces(id int, snmp *gosnmp.GoSNMP) {
	type IfMetric struct {
		Idx                                               int
		Name, Alias                                       string
		SpeedHigh                                         int64
		OperStatus                                        int
		InHc, OutHc, InErr, OutErr, InDisc, OutDisc, OutQ int64
		InMcast, InBcast, OutMcast, OutBcast              int64
	}
	ifMap := make(map[int]*IfMetric)
	getIf := func(idx int) *IfMetric {
		if _, ok := ifMap[idx]; !ok {
			ifMap[idx] = &IfMetric{Idx: idx}
		}
		return ifMap[idx]
	}

	// 1. Walk High Capacity Counters
	snmp.BulkWalk(OID_IF_X_ENTRY, func(pdu gosnmp.SnmpPDU) error {
		if len(pdu.Name) <= len(OID_IF_X_ENTRY) { return nil }
		var idx int
		fmt.Sscanf(pdu.Name[strings.LastIndex(pdu.Name, ".")+1:], "%d", &idx)
		m := getIf(idx)
		oid := pdu.Name[:strings.LastIndex(pdu.Name, ".")]
		switch {
		case strings.HasSuffix(oid, OID_IF_NAME):
			m.Name = string(pdu.Value.([]byte))
		case strings.HasSuffix(oid, OID_IF_ALIAS):
			m.Alias = string(pdu.Value.([]byte))
		case strings.HasSuffix(oid, OID_IF_HIGH_SPEED):
			m.SpeedHigh = gosnmp.ToBigInt(pdu.Value).Int64()
		case strings.HasSuffix(oid, OID_IF_HC_IN_OCT):
			m.InHc = gosnmp.ToBigInt(pdu.Value).Int64()
		case strings.HasSuffix(oid, OID_IF_HC_OUT_OCT):
			m.OutHc = gosnmp.ToBigInt(pdu.Value).Int64()
		case strings.HasSuffix(oid, OID_IF_IN_MCAST):
			m.InMcast = gosnmp.ToBigInt(pdu.Value).Int64()
		case strings.HasSuffix(oid, OID_IF_IN_BCAST):
			m.InBcast = gosnmp.ToBigInt(pdu.Value).Int64()
		case strings.HasSuffix(oid, OID_IF_OUT_MCAST):
			m.OutMcast = gosnmp.ToBigInt(pdu.Value).Int64()
		case strings.HasSuffix(oid, OID_IF_OUT_BCAST):
			m.OutBcast = gosnmp.ToBigInt(pdu.Value).Int64()
		}
		return nil
	})

	// 2. Walk Status & Errors
	snmp.BulkWalk(OID_IF_ENTRY, func(pdu gosnmp.SnmpPDU) error {
		if len(pdu.Name) <= len(OID_IF_ENTRY) { return nil }
		var idx int
		fmt.Sscanf(pdu.Name[strings.LastIndex(pdu.Name, ".")+1:], "%d", &idx)
		if _, ok := ifMap[idx]; !ok { return nil }
		m := ifMap[idx]
		oid := pdu.Name[:strings.LastIndex(pdu.Name, ".")]
		switch {
		case strings.HasSuffix(oid, OID_IF_OPER_STATUS):
			m.OperStatus = int(gosnmp.ToBigInt(pdu.Value).Int64())
		case strings.HasSuffix(oid, OID_IF_OUT_QLEN):
			m.OutQ = gosnmp.ToBigInt(pdu.Value).Int64()
		case strings.HasSuffix(oid, OID_IF_IN_ERRORS):
			m.InErr = gosnmp.ToBigInt(pdu.Value).Int64()
		case strings.HasSuffix(oid, OID_IF_OUT_ERRORS):
			m.OutErr = gosnmp.ToBigInt(pdu.Value).Int64()
		case strings.HasSuffix(oid, OID_IF_IN_DISCARDS):
			m.InDisc = gosnmp.ToBigInt(pdu.Value).Int64()
		case strings.HasSuffix(oid, OID_IF_OUT_DISCARDS):
			m.OutDisc = gosnmp.ToBigInt(pdu.Value).Int64()
		}
		return nil
	})

	q := `INSERT INTO interface_metrics
    (device_id, interface_index, interface_name, alias, oper_status, speed_high,
    hc_in_octets, hc_out_octets, in_mcast_pkts, in_bcast_pkts, out_mcast_pkts, out_bcast_pkts,
    in_errors, out_errors, in_discards, out_discards, out_queue_len)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	stmt, _ := db.Prepare(q)
	defer stmt.Close()

	for _, m := range ifMap {
		if m.Name == "" { continue }
		stmt.Exec(id, m.Idx, m.Name, m.Alias, m.OperStatus, m.SpeedHigh,
			m.InHc, m.OutHc, m.InMcast, m.InBcast, m.OutMcast, m.OutBcast,
			m.InErr, m.OutErr, m.InDisc, m.OutDisc, m.OutQ)

		// --- ALERT CHECK ---
		// If interface is DOWN (OperStatus != 1) and it's not a loopback (lo)
		if m.OperStatus != 1 && m.Name != "lo" {
			createAlert(id, "warning", fmt.Sprintf("Interface DOWN: %s (%s)", m.Name, m.Alias))
		}
	}
}

func collectStorage(id int, snmp *gosnmp.GoSNMP) {
	type Stor struct {
		Idx               int
		Descr             string
		Alloc, Size, Used int64
	}
	sMap := make(map[int]*Stor)
	getS := func(i int) *Stor {
		if _, ok := sMap[i]; !ok {
			sMap[i] = &Stor{Idx: i}
		}
		return sMap[i]
	}

	snmp.BulkWalk(OID_HR_STORAGE_ENTRY, func(pdu gosnmp.SnmpPDU) error {
		if len(pdu.Name) <= len(OID_HR_STORAGE_ENTRY) { return nil }
		var idx int
		fmt.Sscanf(pdu.Name[strings.LastIndex(pdu.Name, ".")+1:], "%d", &idx)
		s := getS(idx)
		oid := pdu.Name[:strings.LastIndex(pdu.Name, ".")]
		switch {
		case strings.HasSuffix(oid, OID_HR_STOR_DESCR):
			s.Descr = string(pdu.Value.([]byte))
		case strings.HasSuffix(oid, OID_HR_STOR_ALLOC):
			s.Alloc = gosnmp.ToBigInt(pdu.Value).Int64()
		case strings.HasSuffix(oid, OID_HR_STOR_SIZE):
			s.Size = gosnmp.ToBigInt(pdu.Value).Int64()
		case strings.HasSuffix(oid, OID_HR_STOR_USED):
			s.Used = gosnmp.ToBigInt(pdu.Value).Int64()
		}
		return nil
	})

	q := `INSERT INTO storage_metrics (device_id, storage_index, storage_descr, size_bytes, used_bytes) VALUES (?,?,?,?,?)`
	stmt, _ := db.Prepare(q)
	defer stmt.Close()
	for _, s := range sMap {
		if s.Size == 0 { continue }
		sizeBytes := s.Size * s.Alloc
		usedBytes := s.Used * s.Alloc
		stmt.Exec(id, s.Idx, s.Descr, sizeBytes, usedBytes)
	}
}

func collectSensors(id int, snmp *gosnmp.GoSNMP) {
	type Sensor struct {
		Idx  int
		Name string
		Val  float64
	}
	sensMap := make(map[int]*Sensor)
	getSens := func(i int) *Sensor {
		if _, ok := sensMap[i]; !ok {
			sensMap[i] = &Sensor{Idx: i}
		}
		return sensMap[i]
	}

	snmp.BulkWalk(OID_LM_TEMP_ENTRY, func(pdu gosnmp.SnmpPDU) error {
		if len(pdu.Name) <= len(OID_LM_TEMP_ENTRY) { return nil }
		var idx int
		fmt.Sscanf(pdu.Name[strings.LastIndex(pdu.Name, ".")+1:], "%d", &idx)
		s := getSens(idx)
		oid := pdu.Name[:strings.LastIndex(pdu.Name, ".")]
		switch {
		case strings.HasSuffix(oid, OID_LM_TEMP_NAME):
			s.Name = string(pdu.Value.([]byte))
		case strings.HasSuffix(oid, OID_LM_TEMP_VAL):
			mC := gosnmp.ToBigInt(pdu.Value).Int64()
			s.Val = float64(mC) / 1000.0
		}
		return nil
	})

	q := `INSERT INTO sensor_metrics (device_id, sensor_name, sensor_type, value) VALUES (?,?,?,?)`
	stmt, _ := db.Prepare(q)
	defer stmt.Close()
	for _, s := range sensMap {
		if s.Name == "" { continue }
		stmt.Exec(id, s.Name, "temperature", s.Val)
	}
}

// --- API HANDLERS ---

func handleDevices(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" { return }

	// CREATE DEVICE
	if r.Method == "POST" {
		var d struct {
			Hostname  string `json:"hostname"`
			Ip        string `json:"ip"`
			Community string `json:"community"`
		}
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			http.Error(w, "Invalid JSON", 400)
			return
		}
		if d.Hostname == "" || d.Ip == "" {
			http.Error(w, "Hostname and IP required", 400)
			return
		}
		if d.Community == "" { d.Community = "public" }

		_, err := db.Exec("INSERT INTO devices (hostname, ip_address, community_string) VALUES (?,?,?)", d.Hostname, d.Ip, d.Community)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		dbLog("INFO", "API", "Added device: "+d.Hostname)
		w.WriteHeader(http.StatusCreated)
		return
	}

	// SEARCH & LIST DEVICES
	query := r.URL.Query().Get("q")
	sqlStr := "SELECT id, hostname, ip_address, COALESCE(sys_descr,''), COALESCE(sys_location,''), is_paused FROM devices"
	var args []interface{}

	if query != "" {
		sqlStr += " WHERE hostname LIKE ? OR ip_address LIKE ?"
		args = append(args, "%"+query+"%", "%"+query+"%")
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
		var h, ip, desc, loc string
		var p bool
		rows.Scan(&id, &h, &ip, &desc, &loc, &p)
		res = append(res, map[string]interface{}{
			"id": id, "hostname": h, "ip": ip, "description": desc, "location": loc, "is_paused": p,
		})
	}
	if res == nil { res = []map[string]interface{}{} }
	json.NewEncoder(w).Encode(res)
}

func handleDeviceAction(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" { return }
	
	var req struct { Action string `json:"action"`; Id int `json:"id"` }
	json.NewDecoder(r.Body).Decode(&req)

	if req.Action == "delete" {
		db.Exec("DELETE FROM devices WHERE id=?", req.Id)
		dbLog("INFO", "API", fmt.Sprintf("Deleted device ID %d", req.Id))
	} else if req.Action == "pause" {
		db.Exec("UPDATE devices SET is_paused=1 WHERE id=?", req.Id)
		dbLog("INFO", "API", fmt.Sprintf("Paused device ID %d", req.Id))
	} else if req.Action == "resume" {
		db.Exec("UPDATE devices SET is_paused=0 WHERE id=?", req.Id)
		dbLog("INFO", "API", fmt.Sprintf("Resumed device ID %d", req.Id))
	}
}

func handleAlerts(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	rows, _ := db.Query(`SELECT a.id, a.severity, a.message, a.created_at, d.hostname 
		FROM alerts a JOIN devices d ON a.device_id = d.id 
		WHERE a.is_active=1 ORDER BY a.created_at DESC LIMIT 50`)
	defer rows.Close()
	var res []map[string]interface{}
	for rows.Next() {
		var id int; var sev, msg, host string; var t time.Time
		rows.Scan(&id, &sev, &msg, &t, &host)
		res = append(res, map[string]interface{}{"id":id,"severity":sev,"message":msg,"time":t.Format("15:04:05"),"hostname":host})
	}
	if res == nil { res = []map[string]interface{}{} }
	json.NewEncoder(w).Encode(res)
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	rows, _ := db.Query("SELECT level, source, message, created_at FROM system_logs ORDER BY created_at DESC LIMIT 100")
	defer rows.Close()
	var res []map[string]interface{}
	for rows.Next() {
		var l, s, m string; var t time.Time
		rows.Scan(&l, &s, &m, &t)
		res = append(res, map[string]interface{}{"level":l,"source":s,"message":m,"time":t.Format("2006-01-02 15:04:05")})
	}
	if res == nil { res = []map[string]interface{}{} }
	json.NewEncoder(w).Encode(res)
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "POST" {
		var settings map[string]interface{}
		json.NewDecoder(r.Body).Decode(&settings)
		for k, v := range settings {
			// Convert various types to string for storage
			strVal := fmt.Sprintf("%v", v)
			db.Exec("INSERT INTO settings (key_name, value_str) VALUES (?,?) ON DUPLICATE KEY UPDATE value_str=?", k, strVal, strVal)
		}
		dbLog("INFO", "API", "Settings updated")
		return
	}
	// GET
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

// COMPLEX DETAIL HANDLER (Fetching History, Protocols, Storage)
func handleDetail(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" { return }

	id := r.URL.Query().Get("id")
	if id == "" { http.Error(w, "Missing ID", 400); return }

	// 1. Health History
	hRows, _ := db.Query(`
		SELECT load_1min, load_5min, load_15min, ram_used, ram_total, swap_used, swap_total, collected_at 
		FROM device_health WHERE device_id=? ORDER BY collected_at DESC LIMIT 30`, id)
	defer hRows.Close()

	var history []map[string]interface{}
	var currentRamTotal, currentSwapTotal int64

	for hRows.Next() {
		var l1, l5, l15 float64
		var ram, ramTot, swap, swapTot int64
		var t time.Time
		hRows.Scan(&l1, &l5, &l15, &ram, &ramTot, &swap, &swapTot, &t)
		currentRamTotal = ramTot
		currentSwapTotal = swapTot
		history = append(history, map[string]interface{}{
			"time": t.Format("15:04"), "load1": l1, "load5": l5, "load15": l15,
			"ram_used": ram / 1024 / 1024, "swap_used": swap / 1024 / 1024,
		})
	}
	// Reverse
	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}

	// 2. Network History
	nRows, _ := db.Query(`
		SELECT collected_at, 
			SUM(hc_in_octets) as total_in, 
			SUM(hc_out_octets) as total_out,
			SUM(in_errors + out_errors) as total_errors
		FROM interface_metrics WHERE device_id=? 
		GROUP BY collected_at ORDER BY collected_at DESC LIMIT 30`, id)
	defer nRows.Close()
	
	var netHistory []map[string]interface{}
	for nRows.Next() {
		var t time.Time
		var in, out, errs int64
		nRows.Scan(&t, &in, &out, &errs)
		netHistory = append(netHistory, map[string]interface{}{
			"time": t.Format("15:04"), "rx_kb": in / 1024, "tx_kb": out / 1024, "errors": errs,
		})
	}
	// Reverse
	for i, j := 0, len(netHistory)-1; i < j; i, j = i+1, j-1 {
		netHistory[i], netHistory[j] = netHistory[j], netHistory[i]
	}

	// 3. Protocols
	pRow := db.QueryRow(`
		SELECT tcp_curr_estab, tcp_in_segs, tcp_out_segs, udp_in_datagrams, udp_out_datagrams, icmp_in_msgs, icmp_out_msgs 
		FROM protocol_metrics WHERE device_id=? ORDER BY collected_at DESC LIMIT 1`, id)
	var tcpEstab, tcpIn, tcpOut, udpIn, udpOut, icmpIn, icmpOut int64
	pRow.Scan(&tcpEstab, &tcpIn, &tcpOut, &udpIn, &udpOut, &icmpIn, &icmpOut)

	// 4. Interfaces
	iRows, _ := db.Query(`
		SELECT interface_name, alias, oper_status, speed_high, 
			hc_in_octets, hc_out_octets, 
			in_ucast_pkts, in_mcast_pkts, in_bcast_pkts,
			in_errors, out_errors, in_discards, out_discards
		FROM interface_metrics 
		WHERE device_id=? AND collected_at = (SELECT MAX(collected_at) FROM interface_metrics WHERE device_id=?)`, id, id)
	defer iRows.Close()
	
	var ifaces []map[string]interface{}
	for iRows.Next() {
		var name, alias string
		var status int
		var speed, in, out, ucast, mcast, bcast, inErr, outErr, inDisc, outDisc int64
		iRows.Scan(&name, &alias, &status, &speed, &in, &out, &ucast, &mcast, &bcast, &inErr, &outErr, &inDisc, &outDisc)
		ifaces = append(ifaces, map[string]interface{}{
			"name": name, "alias": alias, "status": status, "speed": speed,
			"in_bytes": in, "out_bytes": out,
			"pkts": map[string]int64{"unicast": ucast, "multicast": mcast, "broadcast": bcast},
			"errors": inErr + outErr, "discards": inDisc + outDisc,
		})
	}

	// 5. Storage
	sRows, _ := db.Query(`
		SELECT storage_descr, size_bytes, used_bytes FROM storage_metrics 
		WHERE device_id=? AND collected_at = (SELECT MAX(collected_at) FROM storage_metrics WHERE device_id=?)`, id, id)
	defer sRows.Close()
	var storage []map[string]interface{}
	for sRows.Next() {
		var d string; var s, u int64
		sRows.Scan(&d, &s, &u)
		storage = append(storage, map[string]interface{}{"name": d, "size": s, "used": u})
	}
	
	// 6. System Info
	var sysInfo struct { Descr, Uptime, Contact, Location string }
	db.QueryRow("SELECT COALESCE(sys_descr,''), COALESCE(sys_contact,''), COALESCE(sys_location,'') FROM devices WHERE id=?", id).Scan(&sysInfo.Descr, &sysInfo.Contact, &sysInfo.Location)
	var uptime int64
	db.QueryRow("SELECT uptime_seconds FROM device_health WHERE device_id=? ORDER BY collected_at DESC LIMIT 1", id).Scan(&uptime)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"sys_info": map[string]interface{}{
			"descr": sysInfo.Descr, "contact": sysInfo.Contact, "location": sysInfo.Location, "uptime": uptime,
			"ram_total": currentRamTotal, "swap_total": currentSwapTotal,
		},
		"history_health": history, "history_net": netHistory,
		"protocols": map[string]interface{}{
			"tcp": map[string]int64{"estab": tcpEstab, "in": tcpIn, "out": tcpOut},
			"udp": map[string]int64{"in": udpIn, "out": udpOut},
			"icmp": map[string]int64{"in": icmpIn, "out": icmpOut},
		},
		"interfaces": ifaces, "storage": storage,
	})
}
