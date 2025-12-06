package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gosnmp/gosnmp"
)

// --- Config ---
const (
	DB_DSN      = "atharv:QpMz.1793@tcp(127.0.0.1:3306)/network_monitor?parseTime=true"
	HTTP_PORT   = ":8080"
	POLL_TICKER = 60 * time.Second
)

// ... [KEEP ALL YOUR OID CONSTANTS HERE AS IS] ...
// (I am omitting the OID constants to save space, paste them back in here from your original code)
// --- OIDs START ---
const (
	OID_SYS_DESCR    = ".1.3.6.1.2.1.1.1.0"
	OID_SYS_OBJECTID = ".1.3.6.1.2.1.1.2.0"
	OID_SYS_CONTACT  = ".1.3.6.1.2.1.1.4.0"
	OID_SYS_NAME     = ".1.3.6.1.2.1.1.5.0"
	OID_SYS_LOCATION = ".1.3.6.1.2.1.1.6.0"
)
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
const (
	OID_IF_ENTRY        = ".1.3.6.1.2.1.2.2.1"
	OID_IF_OPER_STATUS  = ".8"
	OID_IF_IN_DISCARDS  = ".13"
	OID_IF_IN_ERRORS    = ".14"
	OID_IF_OUT_DISCARDS = ".19"
	OID_IF_OUT_ERRORS   = ".20"
	OID_IF_OUT_QLEN     = ".21"
)
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
const (
	OID_HR_STORAGE_ENTRY = ".1.3.6.1.2.1.25.2.3.1"
	OID_HR_STOR_DESCR    = ".3"
	OID_HR_STOR_ALLOC    = ".4"
	OID_HR_STOR_SIZE     = ".5"
	OID_HR_STOR_USED     = ".6"
)
const (
	OID_LM_TEMP_ENTRY = ".1.3.6.1.4.1.2021.13.16.2.1"
	OID_LM_TEMP_NAME  = ".2"
	OID_LM_TEMP_VAL   = ".3"
)
const (
	OID_TCP_RTO_ALGO   = ".1.3.6.1.2.1.6.1.0"
	OID_TCP_ESTAB      = ".1.3.6.1.2.1.6.9.0"
	OID_TCP_IN_SEGS    = ".1.3.6.1.2.1.6.10.0"
	OID_TCP_OUT_SEGS   = ".1.3.6.1.2.1.6.11.0"
	OID_UDP_IN_DGRAMS  = ".1.3.6.1.2.1.7.1.0"
	OID_UDP_OUT_DGRAMS = ".1.3.6.1.2.1.7.4.0"
	OID_ICMP_IN_MSGS   = ".1.3.6.1.2.1.5.1.0"
	OID_ICMP_OUT_MSGS  = ".1.3.6.1.2.1.5.14.0"
)
// --- OIDs END ---

var db *sql.DB

// Enable CORS for frontend communication
func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}

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

	go startPoller()

	// Handlers
	http.HandleFunc("/api/devices", handleDevices)      // GET list, POST new
	http.HandleFunc("/api/device/detail", handleDetail) // GET detail + metrics

	log.Println("Server running on", HTTP_PORT)
	log.Fatal(http.ListenAndServe(HTTP_PORT, nil))
}

// ... [KEEP ALL YOUR POLLING AND COLLECTION LOGIC HERE AS IS] ...
// (pollAll, collectDevice, collectSystemInfo, etc... No changes needed there)
// PASTE THE POLLING LOGIC FROM ORIGINAL CODE HERE

func startPoller() {
	ticker := time.NewTicker(POLL_TICKER)
	defer ticker.Stop()
	pollAll()
	for range ticker.C {
		pollAll()
	}
}

func pollAll() {
	log.Println("\n--- Polling Start ---")
	rows, err := db.Query("SELECT id, hostname, ip_address, community_string FROM devices")
	if err != nil {
		log.Println("Error fetching devices:", err)
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
	log.Println("--- Polling End ---")
}

func collectDevice(id int, host, ip, comm string) {
	snmp := &gosnmp.GoSNMP{
		Target: ip, Port: 161, Community: comm, Version: gosnmp.Version2c,
		Timeout: 2 * time.Second, Retries: 1,
	}
	if err := snmp.Connect(); err != nil {
		log.Printf("[%s] Connect Fail: %v", host, err)
		return
	}
	defer snmp.Conn.Close()

	collectSystemInfo(id, snmp)
	collectHealthAndProtocols(id, snmp)
	collectInterfaces(id, snmp)
	collectStorage(id, snmp)
	collectSensors(id, snmp)
}

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

	_, err = db.Exec(`UPDATE devices SET sys_descr=?, sys_object_id=?, sys_contact=?, sys_name=?, sys_location=? WHERE id=?`,
		vals[OID_SYS_DESCR], vals[OID_SYS_OBJECTID], vals[OID_SYS_CONTACT], vals[OID_SYS_NAME], vals[OID_SYS_LOCATION], id)
	if err != nil {
		log.Printf("SysInfo Update Error: %v", err)
	}
}

func collectInterfaces(id int, snmp *gosnmp.GoSNMP) {
	type IfMetric struct {
		Idx                                                   int
		Name, Alias                                           string
		SpeedHigh                                             int64
		OperStatus                                            int
		InHc, OutHc, InErr, OutErr, InDisc, OutDisc, OutQ     int64
		InMcast, InBcast, OutMcast, OutBcast                  int64
	}
	ifMap := make(map[int]*IfMetric)

	getIf := func(idx int) *IfMetric {
		if _, ok := ifMap[idx]; !ok {
			ifMap[idx] = &IfMetric{Idx: idx}
		}
		return ifMap[idx]
	}

	// Walk ifXTable (High Capacity)
	snmp.BulkWalk(OID_IF_X_ENTRY, func(pdu gosnmp.SnmpPDU) error {
		if len(pdu.Name) <= len(OID_IF_X_ENTRY) {
			return nil
		}
		var idx int
		fmt.Sscanf(pdu.Name[strings.LastIndex(pdu.Name, ".")+1:], "%d", &idx)
		m := getIf(idx)

		// Prefix matching
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

	// Walk Legacy Table (for Status/Queue/Errors)
	snmp.BulkWalk(OID_IF_ENTRY, func(pdu gosnmp.SnmpPDU) error {
		if len(pdu.Name) <= len(OID_IF_ENTRY) {
			return nil
		}
		var idx int
		fmt.Sscanf(pdu.Name[strings.LastIndex(pdu.Name, ".")+1:], "%d", &idx)
		if _, ok := ifMap[idx]; !ok {
			return nil
		} // Only enrich existing from XTable
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

	// Insert
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
	}
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
		log.Printf("Health Get Err: %v", err)
		return
	}

	v := make(map[string]interface{})
	for _, vb := range res.Variables {
		// Basic parsing
		if vb.Type == gosnmp.OctetString {
			var f float64
			fmt.Sscanf(string(vb.Value.([]byte)), "%f", &f)
			v[vb.Name] = f
		} else {
			v[vb.Name] = gosnmp.ToBigInt(vb.Value).Int64()
		}
	}

	// Calc Used
	ramTot := v[OID_MEM_TOTAL_REAL].(int64) * 1024
	ramAvail := v[OID_MEM_AVAIL_REAL].(int64) * 1024
	swapTot := v[OID_MEM_TOTAL_SWAP].(int64) * 1024
	swapAvail := v[OID_MEM_AVAIL_SWAP].(int64) * 1024
	uptime := v[OID_HR_UPTIME].(int64) / 100

	// Save Health
	db.Exec(`INSERT INTO device_health (device_id, uptime_seconds, load_1min, load_5min, load_15min,
        ram_total, ram_used, swap_total, swap_used) VALUES (?,?,?,?,?,?,?,?,?)`,
		id, uptime, v[OID_UCD_LOAD_1], v[OID_UCD_LOAD_5], v[OID_UCD_LOAD_15],
		ramTot, ramTot-ramAvail, swapTot, swapTot-swapAvail)

	// Save Protocols
	db.Exec(`INSERT INTO protocol_metrics (device_id, tcp_curr_estab, tcp_in_segs, tcp_out_segs,
        udp_in_datagrams, udp_out_datagrams, icmp_in_msgs, icmp_out_msgs) VALUES (?,?,?,?,?,?,?,?)`,
		id, v[OID_TCP_ESTAB], v[OID_TCP_IN_SEGS], v[OID_TCP_OUT_SEGS],
		v[OID_UDP_IN_DGRAMS], v[OID_UDP_OUT_DGRAMS], v[OID_ICMP_IN_MSGS], v[OID_ICMP_OUT_MSGS])
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
		} // Skip empty virtual mounts
		sizeBytes := s.Size * s.Alloc
		usedBytes := s.Used * s.Alloc
		stmt.Exec(id, s.Idx, s.Descr, sizeBytes, usedBytes)
	}
}

func collectSensors(id int, snmp *gosnmp.GoSNMP) {
	// Simple map for temps
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
			// lmSensors returns milliCelsius (1000 = 1C)
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

// --- UPDATED API HANDLERS ---
func handleDevices(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" {
		return
	}

	// POST: Add new device
	if r.Method == "POST" {
		// Use struct tags to ensure JSON matches correctly
		var d struct {
			Hostname  string `json:"hostname"`
			Ip        string `json:"ip"`
			Community string `json:"community"`
		}
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), 400)
			return
		}

		// validiation
		if d.Hostname == "" || d.Ip == "" {
			http.Error(w, "Hostname and IP are required", 400)
			return
		}
		if d.Community == "" {
			d.Community = "public"
		}

		_, err := db.Exec("INSERT INTO devices (hostname, ip_address, community_string) VALUES (?,?,?)", d.Hostname, d.Ip, d.Community)
		if err != nil {
			log.Println("Insert Error:", err) // Log error to console
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusCreated)
		return
	}

	// GET: List all
	// FIXED: Use COALESCE(column, '') to turn NULLs into empty strings so Go doesn't crash
	rows, err := db.Query(`
		SELECT id, hostname, ip_address, 
		COALESCE(sys_descr, '') as sys_descr, 
		COALESCE(sys_location, '') as sys_location 
		FROM devices
	`)
	if err != nil {
		log.Println("Query Error:", err)
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var res []map[string]interface{}
	for rows.Next() {
		var id int
		var h, ip, desc, loc string
		// Now safe to scan because we guaranteed strings in SQL
		if err := rows.Scan(&id, &h, &ip, &desc, &loc); err != nil {
			log.Println("Scan Error:", err)
			continue
		}
		res = append(res, map[string]interface{}{
			"id": id, "hostname": h, "ip": ip, "description": desc, "location": loc,
		})
	}
	
	// Return empty array [] instead of null if no devices
	if res == nil {
		res = []map[string]interface{}{}
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

	// 1. Get History (Last 20 points for charts)
	hRows, _ := db.Query(`SELECT load_1min, load_5min, ram_used, collected_at 
                         FROM device_health WHERE device_id=? ORDER BY collected_at DESC LIMIT 20`, id)
	defer hRows.Close()
	var history []map[string]interface{}
	for hRows.Next() {
		var l1, l5 float64
		var ram int64
		var t time.Time
		hRows.Scan(&l1, &l5, &ram, &t)
		history = append(history, map[string]interface{}{
			"time": t.Format("15:04:05"), "load1": l1, "load5": l5, "ram": ram / 1024 / 1024,
		})
	}
	// Reverse history for chart (Oldest -> Newest)
	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}

	// 2. Get Interfaces (Latest Snapshot)
	// Uses a subquery to get the very last metrics for each interface index
	iRows, _ := db.Query(`
        SELECT interface_name, alias, oper_status, hc_in_octets, hc_out_octets 
        FROM interface_metrics 
        WHERE device_id=? AND collected_at = (SELECT MAX(collected_at) FROM interface_metrics WHERE device_id=?)
    `, id, id)
	defer iRows.Close()
	var ifaces []map[string]interface{}
	for iRows.Next() {
		var name, alias string
		var status int
		var in, out int64
		iRows.Scan(&name, &alias, &status, &in, &out)
		ifaces = append(ifaces, map[string]interface{}{
			"name": name, "alias": alias, "status": status, "in_bytes": in, "out_bytes": out,
		})
	}

	// 3. Get Storage (Latest Snapshot)
	sRows, _ := db.Query(`
        SELECT storage_descr, size_bytes, used_bytes 
        FROM storage_metrics 
        WHERE device_id=? AND collected_at = (SELECT MAX(collected_at) FROM storage_metrics WHERE device_id=?)
    `, id, id)
	defer sRows.Close()
	var storage []map[string]interface{}
	for sRows.Next() {
		var desc string
		var size, used int64
		sRows.Scan(&desc, &size, &used)
		storage = append(storage, map[string]interface{}{
			"name": desc, "size_gb": size / 1024 / 1024 / 1024, "used_gb": used / 1024 / 1024 / 1024,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"history":    history,
		"interfaces": ifaces,
		"storage":    storage,
	})
}
