package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

func startTrapReceiver() {
	tl := gosnmp.NewTrapListener()
	tl.OnNewTrap = func(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
		dbLog("INFO", "TrapReceiver", fmt.Sprintf("Trap received from %s", addr.IP))
		var devId int
		err := db.QueryRow("SELECT id FROM devices WHERE ip_address=?", addr.IP.String()).Scan(&devId)
		if err != nil {
			dbLog("WARNING", "TrapReceiver", "Trap from unknown device: "+addr.IP.String())
			return
		}
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
		createAlert(devId, "critical", msg)
	}
	tl.Params = gosnmp.Default
	if err := tl.Listen("0.0.0.0:162"); err != nil {
		log.Printf("Error listening for traps: %v", err)
		dbLog("ERROR", "TrapReceiver", "Failed to bind port 162: "+err.Error())
	}
}

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
	if err := snmp.Connect(); err != nil {
		dbLog("ERROR", "Poller", fmt.Sprintf("[%s] Socket Error: %v", host, err))
		createAlert(id, "critical", "Device Socket Error: "+err.Error())
		return
	}
	defer snmp.Conn.Close()
	_, err := snmp.Get([]string{OID_SYS_UPTIME})
	if err != nil {
		dbLog("ERROR", "Poller", fmt.Sprintf("[%s] Unreachable: %v", host, err))
		createAlert(id, "critical", "Device Unreachable (Timeout)")
		return
	}
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
	if l5, ok := load5.(float64); ok && l5 > 5.0 {
		createAlert(id, "warning", fmt.Sprintf("High CPU Load (5min): %.2f", l5))
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
	q := `INSERT INTO interface_metrics (device_id, interface_index, interface_name, alias, oper_status, speed_high, hc_in_octets, hc_out_octets, in_mcast_pkts, in_bcast_pkts, out_mcast_pkts, out_bcast_pkts, in_errors, out_errors, in_discards, out_discards, out_queue_len) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	stmt, _ := db.Prepare(q)
	defer stmt.Close()
	for _, m := range ifMap {
		if m.Name == "" {
			continue
		}
		stmt.Exec(id, m.Idx, m.Name, m.Alias, m.OperStatus, m.SpeedHigh, m.InHc, m.OutHc, m.InMcast, m.InBcast, m.OutMcast, m.OutBcast, m.InErr, m.OutErr, m.InDisc, m.OutDisc, m.OutQ)
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
		stmt.Exec(id, s.Idx, s.Descr, s.Size*s.Alloc, s.Used*s.Alloc)
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

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
