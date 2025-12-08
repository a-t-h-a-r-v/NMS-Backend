# GoNMS Backend - Network Management System

A high-performance Go-based SNMP network monitoring backend with RSA-encrypted authentication, dynamic polling, and comprehensive device metrics collection.

## Features

- 🔒 **Secure Authentication**: RSA-2048 encrypted login with JWT session management
- 📊 **Comprehensive Monitoring**: SNMP v2c polling for interfaces, health, storage, protocols, and sensors
- 🚨 **SNMP Trap Receiver**: Real-time alert collection on UDP port 162
- 👥 **Role-Based Access Control**: Admin and user roles with granular device permissions
- 🔍 **Network Discovery**: Automated CIDR-based SNMP scanning
- ⚡ **Dynamic Polling**: Configurable poll intervals and SNMP timeouts
- 📡 **Multi-Metric Collection**: CPU load, memory, network traffic, storage utilization, and temperature sensors
- 📝 **System Logging**: Centralized logging to database with console output

## Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│   React     │◄────►│   Go Backend │◄────►│   MySQL     │
│  Frontend   │ HTTPS│   REST API   │      │  Database   │
└─────────────┘      └──────────────┘      └─────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ SNMP Devices │
                     │ (UDP 161/162)│
                     └──────────────┘
```

## Prerequisites

- **Go**: 1.25.5 or higher
- **MySQL**: 8.0 or higher
- **Network Access**: UDP ports 161 (SNMP), 162 (Traps)
- **Operating System**: Linux, macOS, or Windows

## Installation

### 1. Clone Repository

```bash
git clone
cd
```

### 2. Install Dependencies

```bash
go mod download
```

### 3. Database Setup

Create the MySQL database and import the schema:

```bash
mysql -u root -p
```

```sql
CREATE DATABASE network_monitor CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE network_monitor;

-- Import your SQL schema here (devices, users, sessions, etc.)
```

Required tables:
- `devices` - Network device inventory
- `users` - Authentication and authorization
- `sessions` - JWT token sessions
- `user_device_permissions` - RBAC permissions
- `device_health` - CPU, RAM, uptime metrics
- `interface_metrics` - Network interface statistics
- `storage_metrics` - Disk utilization
- `protocol_metrics` - TCP/UDP/ICMP counters
- `sensor_metrics` - Temperature and hardware sensors
- `alerts` - Active system alerts
- `system_logs` - Application logs
- `settings` - Configuration key-value store

### 4. Environment Configuration

Create a `.env` file in the root directory:

```env
# Database Configuration
DB_USER=root
DB_PASS=your_secure_password
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=network_monitor

# HTTP Server
HTTP_PORT=:8080
```

### 5. Build and Run

```bash
# Development
go run .

# Production Build
go build -o nms-backend
./nms-backend
```

## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth/key` | Retrieve RSA public key for encryption |
| POST | `/api/login` | Authenticate with encrypted credentials |

### Protected Endpoints (Requires Authentication)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth/me` | Get current user profile |
| GET | `/api/devices` | List all accessible devices |
| POST | `/api/devices` | Create new device (Admin/Write) |
| PUT | `/api/devices` | Update device configuration |
| POST | `/api/device/action` | Pause/Resume/Delete device |
| GET | `/api/device/detail?id={id}` | Detailed telemetry for device |
| GET | `/api/alerts` | List active alerts |

### Admin Endpoints (Admin Role Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/logs` | View system logs |
| GET/POST | `/api/settings` | Manage system configuration |
| POST | `/api/scan` | Discover devices via CIDR scan |
| GET/POST/PUT/DELETE | `/api/admin/users` | User management |
| GET/POST | `/api/admin/permissions` | Device permission management |

## Authentication Flow

1. **Client** requests public key: `GET /api/auth/key`
2. **Server** responds with RSA-2048 public key (PEM format)
3. **Client** encrypts JSON payload: `{"username":"admin","password":"password"}`
4. **Client** Base64-encodes ciphertext and sends: `POST /api/login`
5. **Server** decrypts with private key, validates credentials
6. **Server** creates session token, returns JWT + user object
7. **Client** includes `Authorization: Bearer <token>` in all subsequent requests

## SNMP Polling

### Supported OIDs

- **System**: sysDescr, sysContact, sysLocation, sysName, sysUptime
- **Interfaces**: ifXTable (HC counters), ifTable (errors, status)
- **Health**: UCD-SNMP-MIB (load averages, memory)
- **Storage**: HOST-RESOURCES-MIB (disk utilization)
- **Protocols**: TCP/UDP/ICMP statistics
- **Sensors**: LM-SENSORS-MIB (temperature)

### Poll Cycle

```
1. Fetch active devices (WHERE is_paused = 0)
2. For each device (concurrent goroutines):
   a. Connect via SNMPv2c
   b. Ping check (sysUptime)
   c. Collect system info
   d. Collect health metrics
   e. Walk interface table
   f. Walk storage table
   g. Walk sensor table
3. Sleep for poll_interval seconds
4. Repeat
```

### Status Detection

| Status | Condition |
|--------|-----------|
| `up` | Successful SNMP response |
| `down` | Socket error or timeout |
| `unknown` | Never polled |

## Configuration Settings

Settings are stored in the `settings` table and can be modified via `/api/settings`:

| Key | Description | Default |
|-----|-------------|---------|
| `poll_interval` | Seconds between poll cycles | 60 |
| `snmp_timeout` | SNMP request timeout (ms) | 2000 |
| `retention_days` | Metrics retention period | 30 |

## Logging

Logs are written to:
1. **Console** (stdout): Real-time monitoring
2. **Database** (`system_logs` table): Persistent storage

Log levels: `INFO`, `WARNING`, `ERROR`

Example:
```
2025-12-07 10:15:30 [INFO] System: Server started on :8080
2025-12-07 10:16:00 [ERROR] Poller: [Core-SW-01] Unreachable: Timeout
```

## Security Considerations

- ✅ RSA-2048 encryption for login credentials
- ✅ Bcrypt SHA-256 password hashing
- ✅ JWT session tokens with expiration
- ✅ CORS enabled for frontend integration
- ✅ Role-based access control (RBAC)
- ✅ SQL prepared statements (injection prevention)
- ⚠ HTTPS should be configured via reverse proxy (Nginx/Caddy)
- ⚠ Firewall UDP ports 161/162 to trusted networks only

## Troubleshooting

### "DB Connection Error"
```bash
# Verify MySQL is running
systemctl status mysql

# Test connection
mysql -u root -p -h 127.0.0.1 -e "SELECT 1"
```

### "Failed to bind port 162"
```bash
# SNMP traps require root/CAP_NET_BIND_SERVICE
sudo setcap 'cap_net_bind_service=+ep' ./nms-backend
```

### "Device always shows 'down'"
- Verify SNMP community string matches device configuration
- Check firewall rules allow UDP 161 outbound
- Test with `snmpwalk`:
  ```bash
  snmpwalk -v2c -c public 192.168.1.1 system
  ```

## Performance Tuning

- **Concurrent Polling**: Devices are polled in parallel (goroutines)
- **Connection Pooling**: MySQL connection pool managed by `database/sql`
- **Bulk Operations**: Interface/storage data uses prepared statements
- **Rate Limiting**: Network scans use semaphore (50 concurrent)

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-metric`
3. Commit changes: `git commit -am 'Add CPU temperature monitoring'`
4. Push to branch: `git push origin feature/new-metric`
5. Submit a Pull Request

## License

This project is licensed under the MIT License.

## Support

For issues and questions:
- GitHub Issues: <repository-url>/issues
- Documentation: <docs-url>
- Email: atharvshirgurkar@gmail.com
