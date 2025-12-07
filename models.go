package main

import (
	"crypto/rsa"
	"database/sql"
)

// --- Global Variables ---
var (
	db         *sql.DB
	PrivateKey *rsa.PrivateKey
	PublicKey  []byte
)

// --- Auth Context Keys ---
type UserContextKey string

const UserKey UserContextKey = "user"

// --- Structs ---

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Email    string `json:"email"`
}

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
