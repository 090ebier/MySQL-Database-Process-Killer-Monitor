# 🛠️ MySQL Database Process Killer & Monitor

An interactive **MySQL/MariaDB process monitoring & query management** script for **cPanel** and **DirectAdmin** servers.

It helps you quickly identify:
- Which database/user is generating load
- Long-running queries
- Excessive sleeping connections

…and provides safe, confirmation-based options to terminate problematic processes.

---

## ✅ Features

### 📊 Monitoring & Analysis
- TOP databases by active query count
- Databases with longest running queries
- Databases by connection count
- Detailed per-database statistics (users, states, longest queries)
- TOP users by resource usage
- Real-time process monitor (auto-refresh)
- Server summary (threads, uptime, process breakdown)

### ⚡ Kill Operations
- Kill queries for a specific database
- Kill long-running queries (> X seconds)
- Kill all queries for a specific user
- Kill a specific process by ID (PID)
- Kill all sleeping connections
- View full processlist

### 🛠️ Advanced
- Export a report to file
- Check slow query log status
- Show important MySQL variables
- View & clear operation logs

---

## ✅ Supported Environments

- **Panels:** cPanel, DirectAdmin , aapanel
- **Database:** MySQL / MariaDB  
- **Shell:** Bash  
- **Run as:** root (recommended)

---

## 🚀 Quick Run (Recommended)

Run directly from GitHub:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/090ebier/MySQL-Database-Process-Killer-Monitor/refs/heads/main/mk.sh)
````

> Tip: If `curl` is not available, install it or use the "Manual Install" method below.

---

## 📦 Manual Install (Optional)

```bash
curl -Lso mk.sh https://raw.githubusercontent.com/090ebier/MySQL-Database-Process-Killer-Monitor/refs/heads/main/mk.sh
chmod +x mk.sh
./mk.sh
```

---

## 🔐 How Authentication Works

The script automatically detects your control panel and configures MySQL access:

### cPanel

* Uses root MySQL config files:

  * `/root/.my.cnf` (preferred)
  * `/root/my.cnf` (fallback)

### DirectAdmin

* Reads credentials from:

  * `/usr/local/directadmin/conf/mysql.conf`

No credentials are hardcoded inside the script.

---

## 🧪 Safe Testing Example (No Real Load)

To create a visible long-running query without CPU/IO pressure:

```sql
SELECT /*MONITOR_TEST*/ SLEEP(120);
```

This will appear in the process list and can be monitored/killed safely.

---

## 📜 Logs

Logs are written to:

* Default:

  * `/var/log/mysql_killer/mysql_killer.log`
* Fallback (if permission denied):

  * `/root/mysql_killer_logs/mysql_killer.log`

The log includes warnings, errors, and kill operations.

---

## ⚠️ Disclaimer

This script can terminate live database queries.

Use carefully on production servers:

* Always inspect the process details before killing
* Killing queries may interrupt applications or roll back transactions

You are responsible for how you use this tool.

