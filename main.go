package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gosnmp/gosnmp"
	"github.com/joho/godotenv"
)

// --- Config ---
var (
	DB_DSN    string
	HTTP_PORT string
)

// --- OIDs ---
const (
	// System
	OID_SYS_DESCR    = ".1.3.6.1.2.1.1.1.0"
	OID_SYS_OBJECTID = ".1.3.6.1.2.1.1.2.0"
	OID_SYS_CONTACT  = ".1.3.6.1.2.1.1.4.0"
	OID_SYS_NAME     = ".1.3.6.1.2.1.1.5.0"
	OID_SYS_LOCATION = ".1.3.6.1.2.1.1.6.0"
	OID_SYS_UPTIME   = ".1.3.6.1.2.1.1.3.0" // Used for Ping check

	// Interfaces (High Capacity)
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

	// Interfaces (Legacy)
	OID_IF_ENTRY        = ".1.3.6.1.2.1.2.2.1"
	OID_IF_OPER_STATUS  = ".8"
	OID_IF_IN_DISCARDS  = ".13"
	OID_IF_IN_ERRORS    = ".14"
	OID_IF_OUT_DISCARDS = ".19"
	OID_IF_OUT_ERRORS   = ".20"
	OID_IF_OUT_QLEN     = ".21"

	// Health (UCD/Host)
	OID_HR_UPTIME      = ".1.3.6.1.2.1.25.1.1.0"
	OID_UCD_LOAD_1     = ".1.3.6.1.4.1.2021.10.1.3.1"
	OID_UCD_LOAD_5     = ".1.3.6.1.4.1.2021.10.1.3.2"
	OID_UCD_LOAD_15    = ".1.3.6.1.4.1.2021.10.1.3.3"
	OID_MEM_TOTAL_REAL = ".1.3.6.1.4.1.2021.4.5.0"
	OID_MEM_AVAIL_REAL = ".1.3.6.1.4.1.2021.4.6.0"
	OID_MEM_TOTAL_SWAP = ".1.3.6.1.4.1.2021.4.3.0"
	OID_MEM_AVAIL_SWAP = ".1.3.6.1.4.1.2021.4.4.0"

	// Storage
	OID_HR_STORAGE_ENTRY = ".1.3.6.1.2.1.25.2.3.1"
	OID_HR_STOR_DESCR    = ".3"
	OID_HR_STOR_ALLOC    = ".4"
	OID_HR_STOR_SIZE     = ".5"
	OID_HR_STOR_USED     = ".6"

	// Sensors
	OID_LM_TEMP_ENTRY = ".1.3.6.1.4.1.2021.13.16.2.1"
	OID_LM_TEMP_NAME  = ".2"
	OID_LM_TEMP_VAL   = ".3"

	// Protocols
	OID_TCP_ESTAB      = ".1.3.6.1.2.1.6.9.0"
	OID_TCP_IN_SEGS    = ".1.3.6.1.2.1.6.10.0"
	OID_TCP_OUT_SEGS   = ".1.3.6.1.2.1.6.11.0"
	OID_UDP_IN_DGRAMS  = ".1.3.6.1.2.1.7.1.0"
	OID_UDP_OUT_DGRAMS = ".1.3.6.1.2.1.7.4.0"
	OID_ICMP_IN_MSGS   = ".1.3.6.1.2.1.5.1.0"
	OID_ICMP_OUT_MSGS  = ".1.3.6.1.2.1.5.14.0"
)

var db *sql.DB

// --- Initialization ---
func init() {
	_ = godotenv.Load() // Load .env file
	DB_DSN = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		getEnv("DB_USER", "root"),
		getEnv("DB_PASS", "password"),
		getEnv("DB_HOST", "127.0.0.1"),
		getEnv("DB_PORT", "3306"),
		getEnv("DB_NAME", "network_monitor"))
	HTTP_PORT = getEnv("HTTP_PORT", ":8080")
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

	// 1. Start Trap Listener (UDP 162) - Requires Sudo
	go startTrapReceiver()

	// 2. Start Poller
	go startDynamicPoller()

	// 3. API Handlers
	http.HandleFunc("/api/devices", handleDevices)
	http.HandleFunc("/api/device/action", handleDeviceAction)
	http.HandleFunc("/api/device/detail", handleDetail)
	http.HandleFunc("/api/alerts", handleAlerts)
	http.HandleFunc("/api/logs", handleLogs)
	http.HandleFunc("/api/settings", handleSettings)
	http.HandleFunc("/api/scan", handleScan)

	dbLog("INFO", "System", "Server started on "+HTTP_PORT)
	log.Println("Listening for SNMP Traps on 0.0.0.0:162 (Ensure you run with sudo)")
	log.Fatal(http.ListenAndServe(HTTP_PORT, nil))
}

// --- Trap Receiver ---
func startTrapReceiver() {
	tl := gosnmp.NewTrapListener()
	tl.OnNewTrap = func(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
		// Log raw trap arrival
		dbLog("INFO", "TrapReceiver", fmt.Sprintf("Trap received from %s", addr.IP))

		// Find associated device
		var devId int
		err := db.QueryRow("SELECT id FROM devices WHERE ip_address=?", addr.IP.String()).Scan(&devId)
		if err != nil {
			dbLog("WARNING", "TrapReceiver", "Trap from unknown device: "+addr.IP.String())
			return
		}

		// Extract Variables into a message
		var msgParts []string
		for _, v := range packet.Variables {
			if v.Type == gosnmp.OctetString {
				msgParts = append(msgParts, string(v.Value.([]byte)))
			}
		}
		msg := "SNMP Trap: " + strings.Join(msgParts, " | ")
		if len(msgParts) == 0 {
			msg = "SNMP Trap received (Generic)"
		}

		// Create Alert
		createAlert(devId, "critical", msg)
	}

	tl.Params = gosnmp.Default
	
	// Bind to port 162
	if err := tl.Listen("0.0.0.0:162"); err != nil {
		log.Printf("Error listening for traps: %v", err)
		dbLog("ERROR", "TrapReceiver", "Failed to bind port 162: "+err.Error())
	}
}

// --- Dynamic Poller ---
func startDynamicPoller() {
	for {
		interval := getSettingInt("poll_interval", 60)
		dbLog("INFO", "Poller", fmt.Sprintf("Starting poll cycle. Next in %ds", interval))
		pollAll()
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

func pollAll() {
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

	// 1. Open Socket
	if err := snmp.Connect(); err != nil {
		dbLog("ERROR", "Poller", fmt.Sprintf("[%s] Socket Error: %v", host, err))
		createAlert(id, "critical", "Device Socket Error: "+err.Error())
		return
	}
	defer snmp.Conn.Close()

	// 2. Connectivity Check (Ping via SysUpTime)
	// This ensures we detect if the server is offline or blocking UDP
	_, err := snmp.Get([]string{OID_SYS_UPTIME})
	if err != nil {
		dbLog("ERROR", "Poller", fmt.Sprintf("[%s] Unreachable: %v", host, err))
		createAlert(id, "critical", "Device Unreachable (Timeout)")
		return
	}

	// 3. Collect Data
	collectSystemInfo(id, snmp)
	collectHealthAndProtocols(id, snmp)
	collectInterfaces(id, snmp)
	collectStorage(id, snmp)
	collectSensors(id, snmp)
}

// --- Data Collectors ---

func collectSystemInfo(id int, snmp *gosnmp.GoSNMP) {
	oids := []string{OID_SYS_DESCR, OID_SYS_OBJECTID, OID_SYS_CONTACT, OID_SYS_NAME, OID_SYS_LOCATION}
	res, err := snmp.Get(oids)
	if err != nil {
		return
	}

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
	if err != nil {
		return
	}

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

	db.Exec(`INSERT INTO device_health (device_id, uptime_seconds, load_1min, load_5min, load_15min,
        ram_total, ram_used, swap_total, swap_used) VALUES (?,?,?,?,?,?,?,?,?)`,
		id, uptime, v[OID_UCD_LOAD_1], load5, v[OID_UCD_LOAD_15],
		ramTot, ramTot-ramAvail, swapTot, swapTot-swapAvail)

	db.Exec(`INSERT INTO protocol_metrics (device_id, tcp_curr_estab, tcp_in_segs, tcp_out_segs,
        udp_in_datagrams, udp_out_datagrams, icmp_in_msgs, icmp_out_msgs) VALUES (?,?,?,?,?,?,?,?)`,
		id, v[OID_TCP_ESTAB], v[OID_TCP_IN_SEGS], v[OID_TCP_OUT_SEGS],
		v[OID_UDP_IN_DGRAMS], v[OID_UDP_OUT_DGRAMS], v[OID_ICMP_IN_MSGS], v[OID_ICMP_OUT_MSGS])

	// Alert: High Load
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

	// 1. Walk High Capacity
	snmp.BulkWalk(OID_IF_X_ENTRY, func(pdu gosnmp.SnmpPDU) error {
		if len(pdu.Name) <= len(OID_IF_X_ENTRY) {
			return nil
		}
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

	// 2. Walk Legacy (Status/Errors)
	snmp.BulkWalk(OID_IF_ENTRY, func(pdu gosnmp.SnmpPDU) error {
		if len(pdu.Name) <= len(OID_IF_ENTRY) {
			return nil
		}
		var idx int
		fmt.Sscanf(pdu.Name[strings.LastIndex(pdu.Name, ".")+1:], "%d", &idx)
		if _, ok := ifMap[idx]; !ok {
			return nil
		}
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
		if m.Name == "" {
			continue
		}
		stmt.Exec(id, m.Idx, m.Name, m.Alias, m.OperStatus, m.SpeedHigh,
			m.InHc, m.OutHc, m.InMcast, m.InBcast, m.OutMcast, m.OutBcast,
			m.InErr, m.OutErr, m.InDisc, m.OutDisc, m.OutQ)

		// Alert: Interface Down
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
		if len(pdu.Name) <= len(OID_HR_STORAGE_ENTRY) {
			return nil
		}
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
		if s.Size == 0 {
			continue
		}
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
		if len(pdu.Name) <= len(OID_LM_TEMP_ENTRY) {
			return nil
		}
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
		if s.Name == "" {
			continue
		}
		stmt.Exec(id, s.Name, "temperature", s.Val)
	}
}

// --- API & Scan Handlers ---

func handleScan(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
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
	sem := make(chan struct{}, 50) // Concurrency limit

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
				// Try Fetching SysName to verify SNMP
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

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func handleDevices(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" {
		return
	}
	
	// 1. CREATE (POST)
	if r.Method == "POST" {
		var d struct {
			Hostname  string `json:"hostname"`
			Ip        string `json:"ip"`
			Community string `json:"community"`
			Force     bool   `json:"force"`
		}
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			http.Error(w, "Invalid JSON", 400)
			return
		}
		if d.Hostname == "" || d.Ip == "" {
			http.Error(w, "Fields required", 400)
			return
		}
		if d.Community == "" {
			d.Community = "public"
		}

		// Check Duplicate
		var existingId int
		var existingHost string
		err := db.QueryRow("SELECT id, hostname FROM devices WHERE ip_address=?", d.Ip).Scan(&existingId, &existingHost)
		if err == nil {
			// Duplicate Found
			if !d.Force {
				w.WriteHeader(http.StatusConflict) // 409
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "Duplicate IP", "existing_hostname": existingHost, "existing_id": existingId,
				})
				return
			} else {
				// Force Update
				_, err := db.Exec("UPDATE devices SET hostname=?, community_string=?, is_paused=0 WHERE id=?", d.Hostname, d.Community, existingId)
				if err != nil { http.Error(w, err.Error(), 500); return }
				dbLog("INFO", "API", fmt.Sprintf("Overwrote device %d via Scan/Force", existingId))
				w.WriteHeader(http.StatusOK)
				return
			}
		}

		// Insert New
		_, err = db.Exec("INSERT INTO devices (hostname, ip_address, community_string) VALUES (?,?,?)", d.Hostname, d.Ip, d.Community)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		dbLog("INFO", "API", "Added device: "+d.Hostname)
		w.WriteHeader(http.StatusCreated)
		return
	}

	// 2. EDIT (PUT)
	if r.Method == "PUT" {
		var d struct {
			Id        int    `json:"id"`
			Hostname  string `json:"hostname"`
			Ip        string `json:"ip"`
			Community string `json:"community"`
		}
		json.NewDecoder(r.Body).Decode(&d)
		_, err := db.Exec("UPDATE devices SET hostname=?, ip_address=?, community_string=? WHERE id=?", d.Hostname, d.Ip, d.Community, d.Id)
		if err != nil { http.Error(w, err.Error(), 500); return }
		dbLog("INFO", "API", fmt.Sprintf("Updated device ID %d", d.Id))
		w.WriteHeader(http.StatusOK)
		return
	}

	// 3. LIST (GET)
	query := r.URL.Query().Get("q")
	sqlStr := "SELECT id, hostname, ip_address, community_string, COALESCE(sys_descr,''), COALESCE(sys_location,''), is_paused FROM devices"
	var args []interface{}
	if query != "" {
		sqlStr += " WHERE hostname LIKE ? OR ip_address LIKE ?"
		args = append(args, "%"+query+"%", "%"+query+"%")
	}
	rows, _ := db.Query(sqlStr, args...)
	defer rows.Close()
	var res []map[string]interface{}
	for rows.Next() {
		var id int
		var h, ip, comm, desc, loc string
		var p bool
		rows.Scan(&id, &h, &ip, &comm, &desc, &loc, &p)
		res = append(res, map[string]interface{}{
			"id": id, "hostname": h, "ip": ip, "community": comm, "description": desc, "location": loc, "is_paused": p,
		})
	}
	if res == nil {
		res = []map[string]interface{}{}
	}
	json.NewEncoder(w).Encode(res)
}

func handleDeviceAction(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" {
		return
	}
	var req struct {
		Action string `json:"action"`
		Id     int    `json:"id"`
	}
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

func handleLogs(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
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
	enableCors(&w)
	if r.Method == "POST" {
		var settings map[string]interface{}
		json.NewDecoder(r.Body).Decode(&settings)
		for k, v := range settings {
			strVal := fmt.Sprintf("%v", v)
			db.Exec("INSERT INTO settings (key_name, value_str) VALUES (?,?) ON DUPLICATE KEY UPDATE value_str=?", k, strVal, strVal)
		}
		dbLog("INFO", "API", "Settings updated")
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

func handleDetail(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" {
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing ID", 400)
		return
	}

	// 1. History
	hRows, _ := db.Query(`SELECT load_1min, load_5min, load_15min, ram_used, ram_total, swap_used, swap_total, collected_at 
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
	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}

	// 2. Net History
	nRows, _ := db.Query(`SELECT collected_at, SUM(hc_in_octets), SUM(hc_out_octets), SUM(in_errors + out_errors)
        FROM interface_metrics WHERE device_id=? GROUP BY collected_at ORDER BY collected_at DESC LIMIT 30`, id)
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
	for i, j := 0, len(netHistory)-1; i < j; i, j = i+1, j-1 {
		netHistory[i], netHistory[j] = netHistory[j], netHistory[i]
	}

	// 3. Protocols
	var tcpEstab, tcpIn, tcpOut, udpIn, udpOut, icmpIn, icmpOut int64
	db.QueryRow(`SELECT tcp_curr_estab, tcp_in_segs, tcp_out_segs, udp_in_datagrams, udp_out_datagrams, icmp_in_msgs, icmp_out_msgs 
        FROM protocol_metrics WHERE device_id=? ORDER BY collected_at DESC LIMIT 1`, id).Scan(&tcpEstab, &tcpIn, &tcpOut, &udpIn, &udpOut, &icmpIn, &icmpOut)

	// 4. Interfaces
	iRows, _ := db.Query(`SELECT interface_name, alias, oper_status, speed_high, hc_in_octets, hc_out_octets, in_ucast_pkts, in_mcast_pkts, in_bcast_pkts, in_errors, out_errors, in_discards, out_discards
        FROM interface_metrics WHERE device_id=? AND collected_at = (SELECT MAX(collected_at) FROM interface_metrics WHERE device_id=?)`, id, id)
	defer iRows.Close()
	var ifaces []map[string]interface{}
	for iRows.Next() {
		var name, alias string
		var status int
		var speed, in, out, ucast, mcast, bcast, inErr, outErr, inDisc, outDisc int64
		iRows.Scan(&name, &alias, &status, &speed, &in, &out, &ucast, &mcast, &bcast, &inErr, &outErr, &inDisc, &outDisc)
		ifaces = append(ifaces, map[string]interface{}{
			"name": name, "alias": alias, "status": status, "speed": speed, "in_bytes": in, "out_bytes": out,
			"pkts": map[string]int64{"unicast": ucast, "multicast": mcast, "broadcast": bcast}, "errors": inErr + outErr, "discards": inDisc + outDisc,
		})
	}

	// 5. Storage
	sRows, _ := db.Query(`SELECT storage_descr, size_bytes, used_bytes FROM storage_metrics WHERE device_id=? AND collected_at = (SELECT MAX(collected_at) FROM storage_metrics WHERE device_id=?)`, id, id)
	defer sRows.Close()
	var storage []map[string]interface{}
	for sRows.Next() {
		var d string
		var s, u int64
		sRows.Scan(&d, &s, &u)
		storage = append(storage, map[string]interface{}{"name": d, "size": s, "used": u})
	}

	// 6. Sys Info
	var sysInfo struct{ Descr, Uptime, Contact, Location string }
	db.QueryRow("SELECT COALESCE(sys_descr,''), COALESCE(sys_contact,''), COALESCE(sys_location,'') FROM devices WHERE id=?", id).Scan(&sysInfo.Descr, &sysInfo.Contact, &sysInfo.Location)
	var uptime int64
	db.QueryRow("SELECT uptime_seconds FROM device_health WHERE device_id=? ORDER BY collected_at DESC LIMIT 1", id).Scan(&uptime)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"sys_info":       map[string]interface{}{"descr": sysInfo.Descr, "contact": sysInfo.Contact, "location": sysInfo.Location, "uptime": uptime, "ram_total": currentRamTotal, "swap_total": currentSwapTotal},
		"history_health": history, "history_net": netHistory,
		"protocols":  map[string]interface{}{"tcp": map[string]int64{"estab": tcpEstab, "in": tcpIn, "out": tcpOut}, "udp": map[string]int64{"in": udpIn, "out": udpOut}, "icmp": map[string]int64{"in": icmpIn, "out": icmpOut}},
		"interfaces": ifaces, "storage": storage,
	})
}

// --- Helpers ---
func dbLog(level, source, msg string) {
	log.Printf("[%s] %s: %s", level, source, msg)
	go func() {
		db.Exec("INSERT INTO system_logs (level, source, message) VALUES (?,?,?)", level, source, msg)
	}()
}

func getSettingInt(key string, def int) int {
	var val string
	if err := db.QueryRow("SELECT value_str FROM settings WHERE key_name=?", key).Scan(&val); err != nil {
		return def
	}
	i, _ := strconv.Atoi(val)
	return i
}

func createAlert(devId int, severity, msg string) {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM alerts WHERE device_id=? AND message=? AND is_active=1", devId, msg).Scan(&count)
	if count == 0 {
		db.Exec("INSERT INTO alerts (device_id, severity, message) VALUES (?,?,?)", devId, severity, msg)
	}
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type")
}
