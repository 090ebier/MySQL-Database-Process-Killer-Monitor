#!/usr/bin/env bash
#
# MySQL Database Process Killer & Monitor
# سازگار با cPanel و DirectAdmin
# نسخه: 3.0 - Advanced Monitoring
#

set -euo pipefail

# رنگ‌ها برای خروجی بهتر
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# مسیر لاگ
LOG_DIR="/var/log/mysql_killer"
LOG_FILE="${LOG_DIR}/mysql_killer.log"

# ایجاد دایرکتوری لاگ
init_logging() {
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR" 2>/dev/null || {
            LOG_DIR="/root/mysql_killer_logs"
            LOG_FILE="${LOG_DIR}/mysql_killer.log"
            mkdir -p "$LOG_DIR" 2>/dev/null || {
                print_warning "Cannot create log directory. Logging disabled."
                LOG_FILE="/dev/null"
                return 1
            }
        }
    fi
    
    touch "$LOG_FILE" 2>/dev/null || {
        print_warning "Cannot write to log file. Logging disabled."
        LOG_FILE="/dev/null"
        return 1
    }
    
    # تنظیم دسترسی
    chmod 600 "$LOG_FILE" 2>/dev/null
    
    return 0
}

# تابع لاگ‌گیری
log_action() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE"
}

# لاگ با جزئیات بیشتر
log_kill_action() {
    local action="$1"
    local target="$2"
    local count="$3"
    local details="${4:-}"
    
    log_action "KILL" "Action: ${action} | Target: ${target} | Count: ${count} | Details: ${details}"
}

# توابع کمکی
print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    log_action "INFO" "$1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    log_action "WARNING" "$1"
}

print_header() {
    echo -e "${CYAN}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║          $1${NC}"
    echo -e "${CYAN}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# تابع نمایش منو
show_menu() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   MySQL Database Process Killer & Monitor v3.0            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${MAGENTA}${BOLD}📊 Monitoring & Analysis:${NC}"
    echo "  1) 🔥 Show TOP databases by query count"
    echo "  2) ⏱️  Show databases with longest queries"
    echo "  3) 💾 Show databases by connections count"
    echo "  4) 📈 Show detailed database statistics"
    echo "  5) 👥 Show TOP users by resource usage"
    echo "  6) 🔍 Real-time process monitor (auto-refresh)"
    echo "  7) 📊 Show server load summary"
    echo
    echo -e "${RED}${BOLD}⚡ Kill Operations:${NC}"
    echo "  8)  Kill queries for specific database"
    echo "  9)  Show active processes for database"
    echo "  10) Kill long-running queries (>X seconds)"
    echo "  11) Kill all queries for a user"
    echo "  12) Kill specific process by ID"
    echo "  13) Show full processlist"
    echo "  14) Kill all sleeping connections"
    echo
    echo -e "${BLUE}${BOLD}🛠️  Advanced:${NC}"
    echo "  15) Export report to file"
    echo "  16) Check slow query log status"
    echo "  17) Show MySQL variables"
    echo "  18) 📜 View operation logs"
    echo "  19) 🗑️  Clear old logs"
    echo "  20) Exit"
    echo
}

# تابع پاکسازی
cleanup() {
    [[ -n "${TMP_CNF:-}" && -f "$TMP_CNF" ]] && rm -f "$TMP_CNF"
}
trap cleanup EXIT

# تشخیص پنل کنترل
detect_panel() {
    local panel="unknown"
    
    if [[ -f /usr/local/cpanel/cpanel ]] || [[ -d /var/cpanel ]] || [[ -f /etc/cpanel/cpanel.config ]]; then
        panel="cpanel"
    elif [[ -f /usr/local/directadmin/directadmin ]] || [[ -f /usr/local/directadmin/conf/mysql.conf ]]; then
        panel="directadmin"
    fi
    
    echo "$panel"
}

# راه‌اندازی MySQL برای cPanel
setup_cpanel_mysql() {
    if [[ ! -f /root/.my.cnf ]]; then
        print_warning "/root/.my.cnf not found. Trying /root/my.cnf..."
        if [[ ! -f /root/my.cnf ]]; then
            print_error "Neither /root/.my.cnf nor /root/my.cnf found."
            return 1
        fi
        MYSQL_CNF="/root/my.cnf"
    else
        MYSQL_CNF="/root/.my.cnf"
    fi
    
    MYSQL_CMD=(mysql --batch --skip-column-names --defaults-extra-file="$MYSQL_CNF")
    MYSQL_USER="root"
    return 0
}

# راه‌اندازی MySQL برای DirectAdmin
setup_da_mysql() {
    local da_conf="/usr/local/directadmin/conf/mysql.conf"
    
    if [[ ! -f "$da_conf" ]]; then
        print_error "DirectAdmin mysql.conf not found at $da_conf"
        return 1
    fi
    
    local da_user da_pass
    da_user=$(awk -F= '$1 ~ /^user$/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$da_conf")
    da_pass=$(awk -F= '$1 ~ /^(passwd|password)$/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$da_conf")
    
    [[ -z "$da_user" ]] && da_user="da_admin"
    
    if [[ -z "$da_pass" ]]; then
        print_error "Could not read MySQL password from $da_conf"
        return 1
    fi
    
    TMP_CNF="$(mktemp /tmp/mysqlclient.XXXXXX.cnf)"
    chmod 600 "$TMP_CNF"
    cat > "$TMP_CNF" <<EOF
[client]
user=${da_user}
password=${da_pass}
host=localhost
EOF
    
    MYSQL_CMD=(mysql --batch --skip-column-names --defaults-extra-file="$TMP_CNF")
    MYSQL_USER="$da_user"
    return 0
}

# نمایش دیتابیس‌ها با بیشترین تعداد کوئری
show_top_databases_by_queries() {
    print_header "TOP Databases by Active Query Count"
    
    local query="
    SELECT 
        COALESCE(db, 'NULL') as database_name,
        COUNT(*) as query_count,
        SUM(CASE WHEN command='Query' THEN 1 ELSE 0 END) as active_queries,
        SUM(CASE WHEN command='Sleep' THEN 1 ELSE 0 END) as sleeping,
        ROUND(AVG(time), 2) as avg_time,
        MAX(time) as max_time,
        GROUP_CONCAT(DISTINCT user SEPARATOR ', ') as users
    FROM information_schema.processlist
    WHERE user != '${MYSQL_USER}'
    GROUP BY db
    ORDER BY active_queries DESC, query_count DESC
    LIMIT 20;
    "
    
    echo -e "${BOLD}Database Name | Total | Active | Sleep | Avg(s) | Max(s) | Users${NC}"
    echo "─────────────────────────────────────────────────────────────────────────────"
    
    "${MYSQL_CMD[@]}" -e "$query" | while IFS=$'\t' read -r db count active sleep avg_t max_t users; do
        # رنگ‌آمیزی بر اساس تعداد
        if [[ $active -gt 50 ]]; then
            color="${RED}${BOLD}"
        elif [[ $active -gt 20 ]]; then
            color="${YELLOW}"
        elif [[ $active -gt 5 ]]; then
            color="${CYAN}"
        else
            color="${GREEN}"
        fi
        
        printf "${color}%-25s${NC} | %-5s | ${color}%-6s${NC} | %-5s | %-6s | %-6s | %s\n" \
            "${db:0:25}" "$count" "$active" "$sleep" "$avg_t" "$max_t" "${users:0:30}"
    done
    
    echo
    print_info "Legend: ${RED}Critical (>50)${NC} | ${YELLOW}High (>20)${NC} | ${CYAN}Medium (>5)${NC} | ${GREEN}Normal${NC}"
}

# نمایش دیتابیس‌ها با طولانی‌ترین کوئری‌ها
show_databases_with_longest_queries() {
    print_header "Databases with Longest Running Queries"
    
    local query="
    SELECT 
        COALESCE(db, 'NULL') as database_name,
        MAX(time) as longest_query,
        COUNT(*) as total_processes,
        user,
        state,
        LEFT(info, 80) as query_sample
    FROM information_schema.processlist
    WHERE command='Query' AND user != '${MYSQL_USER}' AND time > 0
    GROUP BY db, user, state, info
    ORDER BY longest_query DESC
    LIMIT 20;
    "
    
    echo -e "${BOLD}Time(s) | Database | User | State | Query Sample${NC}"
    echo "─────────────────────────────────────────────────────────────────────────────"
    
    "${MYSQL_CMD[@]}" -e "$query" | while IFS=$'\t' read -r db time count user state query_text; do
        if [[ $time -gt 300 ]]; then
            color="${RED}${BOLD}"
        elif [[ $time -gt 60 ]]; then
            color="${YELLOW}"
        else
            color="${CYAN}"
        fi
        
        printf "${color}%-7s${NC} | %-20s | %-15s | %-20s | %s\n" \
            "$time" "${db:0:20}" "${user:0:15}" "${state:0:20}" "${query_text:0:50}"
    done
    
    echo
    print_info "Queries running for: ${RED}>300s = Critical${NC} | ${YELLOW}>60s = Warning${NC}"
}

# نمایش دیتابیس‌ها بر اساس تعداد کانکشن
show_databases_by_connections() {
    print_header "Databases by Connection Count"
    
    local query="
    SELECT 
        COALESCE(db, 'NULL') as database_name,
        COUNT(DISTINCT id) as total_connections,
        COUNT(DISTINCT user) as unique_users,
        SUM(CASE WHEN command='Sleep' THEN 1 ELSE 0 END) as idle_connections,
        GROUP_CONCAT(DISTINCT host SEPARATOR ', ') as hosts
    FROM information_schema.processlist
    WHERE user != '${MYSQL_USER}'
    GROUP BY db
    ORDER BY total_connections DESC
    LIMIT 20;
    "
    
    echo -e "${BOLD}Database | Connections | Users | Idle | Hosts${NC}"
    echo "─────────────────────────────────────────────────────────────────────────────"
    
    "${MYSQL_CMD[@]}" -e "$query" | while IFS=$'\t' read -r db conns users idle hosts; do
        if [[ $conns -gt 100 ]]; then
            color="${RED}${BOLD}"
        elif [[ $conns -gt 50 ]]; then
            color="${YELLOW}"
        else
            color="${GREEN}"
        fi
        
        printf "${color}%-25s${NC} | ${color}%-11s${NC} | %-5s | %-4s | %s\n" \
            "${db:0:25}" "$conns" "$users" "$idle" "${hosts:0:40}"
    done
    
    echo
}

# آمار دقیق یک دیتابیس
show_database_detailed_stats() {
    read -rp "Enter database name: " dbname
    [[ -z "$dbname" ]] && { print_error "Database name required."; return; }
    
    print_header "Detailed Statistics for Database: $dbname"
    
    # آمار کلی
    local total_queries sleeping active_queries max_time avg_time
    
    read -r total_queries sleeping active_queries max_time avg_time < <(
        "${MYSQL_CMD[@]}" -e "
        SELECT 
            COUNT(*),
            SUM(CASE WHEN command='Sleep' THEN 1 ELSE 0 END),
            SUM(CASE WHEN command='Query' THEN 1 ELSE 0 END),
            MAX(time),
            ROUND(AVG(time), 2)
        FROM information_schema.processlist
        WHERE db='${dbname}';
        "
    )
    
    echo -e "${CYAN}Overview:${NC}"
    echo "  Total Processes: ${BOLD}$total_queries${NC}"
    echo "  Active Queries: ${BOLD}$active_queries${NC}"
    echo "  Sleeping: ${BOLD}$sleeping${NC}"
    echo "  Max Query Time: ${BOLD}${max_time}s${NC}"
    echo "  Avg Query Time: ${BOLD}${avg_time}s${NC}"
    echo
    
    # کاربران
    echo -e "${CYAN}Users:${NC}"
    "${MYSQL_CMD[@]}" -e "
    SELECT user, COUNT(*) as connections
    FROM information_schema.processlist
    WHERE db='${dbname}'
    GROUP BY user;
    " | column -t -s $'\t'
    echo
    
    # Query states
    echo -e "${CYAN}Query States:${NC}"
    "${MYSQL_CMD[@]}" -e "
    SELECT COALESCE(state, 'NULL') as state, COUNT(*) as count
    FROM information_schema.processlist
    WHERE db='${dbname}' AND command='Query'
    GROUP BY state
    ORDER BY count DESC;
    " | column -t -s $'\t'
    echo
    
    # طولانی‌ترین کوئری‌ها
    echo -e "${CYAN}Top 5 Longest Queries:${NC}"
    "${MYSQL_CMD[@]}" -e "
    SELECT id, user, time, LEFT(info, 100) as query
    FROM information_schema.processlist
    WHERE db='${dbname}' AND command='Query'
    ORDER BY time DESC
    LIMIT 5;
    " | column -t -s $'\t'
    echo
}

# نمایش کاربران با بیشترین استفاده
show_top_users() {
    print_header "TOP Users by Resource Usage"
    
    local query="
    SELECT 
        user,
        COUNT(*) as total_processes,
        SUM(CASE WHEN command='Query' THEN 1 ELSE 0 END) as active_queries,
        SUM(CASE WHEN command='Sleep' THEN 1 ELSE 0 END) as sleeping,
        ROUND(AVG(time), 2) as avg_time,
        MAX(time) as max_time,
        COUNT(DISTINCT db) as databases_used
    FROM information_schema.processlist
    WHERE user != '${MYSQL_USER}' AND user != 'system user'
    GROUP BY user
    ORDER BY active_queries DESC, total_processes DESC
    LIMIT 15;
    "
    
    echo -e "${BOLD}User | Total | Active | Sleep | Avg(s) | Max(s) | DBs${NC}"
    echo "─────────────────────────────────────────────────────────────────────────────"
    
    "${MYSQL_CMD[@]}" -e "$query" | while IFS=$'\t' read -r user total active sleep avg_t max_t dbs; do
        if [[ $active -gt 20 ]]; then
            color="${RED}${BOLD}"
        elif [[ $active -gt 10 ]]; then
            color="${YELLOW}"
        else
            color="${GREEN}"
        fi
        
        printf "${color}%-20s${NC} | %-5s | ${color}%-6s${NC} | %-5s | %-6s | %-6s | %s\n" \
            "${user:0:20}" "$total" "$active" "$sleep" "$avg_t" "$max_t" "$dbs"
    done
    
    echo
}

# مانیتور Real-time
realtime_monitor() {
    local refresh_rate=3
    read -rp "Refresh interval in seconds [default: 3]: " input_rate
    [[ -n "$input_rate" ]] && refresh_rate=$input_rate
    
    print_info "Starting real-time monitor (refresh every ${refresh_rate}s). Press Ctrl+C to stop..."
    sleep 2
    
    while true; do
        clear
        print_header "Real-Time Process Monitor - $(date '+%Y-%m-%d %H:%M:%S')"
        
        # خلاصه سرور
        local total_proc active_queries sleeping max_time
        read -r total_proc active_queries sleeping max_time < <(
            "${MYSQL_CMD[@]}" -e "
            SELECT 
                COUNT(*),
                SUM(CASE WHEN command='Query' THEN 1 ELSE 0 END),
                SUM(CASE WHEN command='Sleep' THEN 1 ELSE 0 END),
                MAX(time)
            FROM information_schema.processlist;
            "
        )
        
        echo -e "${BOLD}Server Summary:${NC} Total: $total_proc | Active: ${YELLOW}$active_queries${NC} | Sleep: $sleeping | Max Time: ${RED}${max_time}s${NC}"
        echo
        
        # TOP 10 active queries
        echo -e "${BOLD}TOP 10 Active Queries:${NC}"
        echo "─────────────────────────────────────────────────────────────────────────────"
        "${MYSQL_CMD[@]}" -e "
        SELECT id, user, db, time, LEFT(info, 60) as query
        FROM information_schema.processlist
        WHERE command='Query' AND user != '${MYSQL_USER}'
        ORDER BY time DESC
        LIMIT 10;
        " | column -t -s $'\t'
        
        sleep "$refresh_rate"
    done
}

# خلاصه وضعیت سرور
show_server_summary() {
    print_header "Server Load Summary"
    
    # MySQL status
    echo -e "${CYAN}${BOLD}MySQL Status:${NC}"
    local uptime threads_conn threads_running queries
    read -r uptime threads_conn threads_running queries < <(
        "${MYSQL_CMD[@]}" -e "
        SELECT 
            VARIABLE_VALUE 
        FROM information_schema.GLOBAL_STATUS 
        WHERE VARIABLE_NAME IN ('Uptime', 'Threads_connected', 'Threads_running', 'Queries')
        ORDER BY VARIABLE_NAME;
        " | xargs
    )
    
    local uptime_hours=$((uptime / 3600))
    echo "  Uptime: ${BOLD}${uptime_hours} hours${NC}"
    echo "  Threads Connected: ${BOLD}$threads_conn${NC}"
    echo "  Threads Running: ${BOLD}$threads_running${NC}"
    echo "  Total Queries: ${BOLD}$queries${NC}"
    echo
    
    # Process summary
    echo -e "${CYAN}${BOLD}Process Summary:${NC}"
    "${MYSQL_CMD[@]}" -e "
    SELECT 
        command,
        COUNT(*) as count,
        ROUND(AVG(time), 2) as avg_time,
        MAX(time) as max_time
    FROM information_schema.processlist
    GROUP BY command
    ORDER BY count DESC;
    " | column -t -s $'\t'
    echo
    
    # Database count
    echo -e "${CYAN}${BOLD}Active Databases:${NC}"
    local db_count
    db_count=$("${MYSQL_CMD[@]}" -e "
    SELECT COUNT(DISTINCT db) 
    FROM information_schema.processlist 
    WHERE db IS NOT NULL;
    ")
    echo "  Total: ${BOLD}$db_count databases${NC}"
    echo
    
    # System load (if available)
    if command -v uptime &> /dev/null; then
        echo -e "${CYAN}${BOLD}System Load:${NC}"
        uptime
        echo
    fi
}

# نمایش لیست پروسس‌ها
show_processlist() {
    local db="${1:-}"
    local query="SELECT id, user, host, db, command, time, state, LEFT(info, 50) as query FROM information_schema.processlist"
    
    if [[ -n "$db" ]]; then
        query="$query WHERE db='$db'"
    fi
    
    query="$query ORDER BY time DESC;"
    
    print_info "Active processes:"
    echo
    "${MYSQL_CMD[@]}" -e "$query" | column -t -s $'\t'
    echo
}

# کشتن کوئری‌های یک دیتابیس خاص
kill_db_queries() {
    local db="$1"
    local command_filter="${2:-Query}"
    
    print_info "Searching for processes in database: $db (Command: $command_filter)"
    log_action "INFO" "Searching processes in DB: $db, Command: $command_filter"
    
    local ids
    ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE db='${db}' AND command='${command_filter}' AND user != '${MYSQL_USER}';" 2>/dev/null || true)
    
    if [[ -z "${ids//[[:space:]]/}" ]]; then
        print_warning "No processes found for database '$db' with command '$command_filter'."
        return 0
    fi
    
    local count
    count=$(echo "$ids" | grep -c . || echo 0)
    
    print_warning "Found $count process(es). Kill them? (y/n): "
    read -r confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        print_info "Aborted."
        log_action "INFO" "Kill operation aborted by user for DB: $db"
        return 0
    fi
    
    local killed=0
    local failed=0
    
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        
        if "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1; then
            ((killed++))
            echo -ne "\r${GREEN}[✓]${NC} Killed: $killed/$count"
        else
            ((failed++))
        fi
    done <<< "$ids"
    
    echo
    print_success "Killed $killed process(es)."
    log_kill_action "Kill DB Queries" "$db" "$killed" "Command: $command_filter, Failed: $failed"
    [[ $failed -gt 0 ]] && print_warning "Failed to kill $failed process(es)."
}

# کشتن کوئری‌های طولانی
kill_long_queries() {
    local min_time="${1:-60}"
    
    print_info "Searching for queries running longer than $min_time seconds..."
    log_action "INFO" "Searching long queries (>${min_time}s)"
    
    local ids
    ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE command='Query' AND time > ${min_time} AND user != '${MYSQL_USER}';" 2>/dev/null || true)
    
    if [[ -z "${ids//[[:space:]]/}" ]]; then
        print_warning "No long-running queries found."
        return 0
    fi
    
    print_info "Long-running queries:"
    "${MYSQL_CMD[@]}" -e "SELECT id, user, db, time, LEFT(info, 100) FROM information_schema.processlist WHERE command='Query' AND time > ${min_time} AND user != '${MYSQL_USER}';" | column -t -s 

# کشتن تمام کانکشن‌های Sleep
kill_sleeping_connections() {
    local db="${1:-}"
    
    local where_clause="command='Sleep'"
    [[ -n "$db" ]] && where_clause="$where_clause AND db='$db'"
    where_clause="$where_clause AND user != '${MYSQL_USER}'"
    
    print_info "Searching for sleeping connections..."
    log_action "INFO" "Searching sleeping connections, DB: ${db:-all}"
    
    local ids
    ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE ${where_clause};" 2>/dev/null || true)
    
    if [[ -z "${ids//[[:space:]]/}" ]]; then
        print_warning "No sleeping connections found."
        return 0
    fi
    
    local count
    count=$(echo "$ids" | grep -c . || echo 0)
    
    print_warning "Found $count sleeping connection(s). Kill them? (y/n): "
    read -r confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_action "INFO" "Kill sleeping connections aborted by user"
        return 0
    fi
    
    local killed=0
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1 && ((killed++))
    done <<< "$ids"
    
    print_success "Killed $killed sleeping connection(s)."
    log_kill_action "Kill Sleeping Connections" "${db:-all}" "$killed" "Command: Sleep"
}

# کشتن پروسس‌های یک کاربر
kill_user_queries() {
    local username="$1"
    
    print_info "Searching for processes by user: $username"
    
    local ids
    ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE user='${username}' AND user != '${MYSQL_USER}';" 2>/dev/null || true)
    
    if [[ -z "${ids//[[:space:]]/}" ]]; then
        print_warning "No processes found for user '$username'."
        return 0
    fi
    
    "${MYSQL_CMD[@]}" -e "SELECT id, db, command, time, state FROM information_schema.processlist WHERE user='${username}';" | column -t -s $'\t'
    echo
    
    local count
    count=$(echo "$ids" | grep -c . || echo 0)
    
    print_warning "Kill $count process(es) for user '$username'? (y/n): "
    read -r confirm
    
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return 0
    
    local killed=0
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1 && ((killed++))
    done <<< "$ids"
    
    print_success "Killed $killed process(es)."
}

# کشتن یک پروسس خاص
kill_specific_process() {
    local pid="$1"
    
    local exists
    exists=$("${MYSQL_CMD[@]}" -e "SELECT COUNT(*) FROM information_schema.processlist WHERE id=${pid};" 2>/dev/null || echo "0")
    
    if [[ "$exists" == "0" ]]; then
        print_error "Process ID $pid not found."
        return 1
    fi
    
    print_info "Process details:"
    "${MYSQL_CMD[@]}" -e "SELECT * FROM information_schema.processlist WHERE id=${pid}\\G"
    echo
    
    print_warning "Kill this process? (y/n): "
    read -r confirm
    
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return 0
    
    if "${MYSQL_CMD[@]}" -e "KILL ${pid};" >/dev/null 2>&1; then
        print_success "Process $pid killed successfully."
    else
        print_error "Failed to kill process $pid."
        return 1
    fi
}

# Export گزارش
export_report() {
    local filename="mysql_report_$(date +%Y%m%d_%H%M%S).txt"
    
    print_info "Generating report..."
    
    {
        echo "======================================================================"
        echo "MySQL Server Report"
        echo "Generated: $(date)"
        echo "======================================================================"
        echo
        
        echo "=== Server Summary ==="
        "${MYSQL_CMD[@]}" -e "
        SELECT VARIABLE_NAME, VARIABLE_VALUE 
        FROM information_schema.GLOBAL_STATUS 
        WHERE VARIABLE_NAME IN ('Uptime', 'Threads_connected', 'Threads_running', 'Questions', 'Queries');" | column -t -s $'\t'
        echo
        
        echo "=== TOP Databases by Query Count ==="
        "${MYSQL_CMD[@]}" -e "
        SELECT COALESCE(db, 'NULL') as database_name, COUNT(*) as count
        FROM information_schema.processlist
        WHERE user != '${MYSQL_USER}'
        GROUP BY db ORDER BY count DESC LIMIT 20;" | column -t -s $'\t'
        echo
        
        echo "=== Active Processes ==="
        "${MYSQL_CMD[@]}" -e "
        SELECT id, user, db, command, time, state, LEFT(info, 100)
        FROM information_schema.processlist
        ORDER BY time DESC;" | column -t -s $'\t'
        
    } > "$filename"
    
    print_success "Report saved to: $filename"
}

# بررسی Slow Query Log
check_slow_query_log() {
    print_header "Slow Query Log Status"
    
    "${MYSQL_CMD[@]}" -e "
    SELECT VARIABLE_NAME, VARIABLE_VALUE 
    FROM information_schema.GLOBAL_VARIABLES 
    WHERE VARIABLE_NAME IN ('slow_query_log', 'slow_query_log_file', 'long_query_time');" | column -t -s $'\t'
    echo
    
    local log_enabled
    log_enabled=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_VARIABLES WHERE VARIABLE_NAME='slow_query_log';")
    
    if [[ "$log_enabled" == "ON" ]]; then
        print_success "Slow query log is enabled"
        local log_file
        log_file=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_VARIABLES WHERE VARIABLE_NAME='slow_query_log_file';")
        
        if [[ -f "$log_file" ]]; then
            print_info "Log file: $log_file"
            print_info "Last 10 entries:"
            tail -n 20 "$log_file" 2>/dev/null || print_warning "Cannot read log file"
        fi
    else
        print_warning "Slow query log is disabled"
        print_info "To enable: SET GLOBAL slow_query_log = 'ON';"
    fi
}

# نمایش MySQL Variables
show_mysql_variables() {
    print_header "Important MySQL Variables"
    
    "${MYSQL_CMD[@]}" -e "
    SELECT VARIABLE_NAME, VARIABLE_VALUE 
    FROM information_schema.GLOBAL_VARIABLES 
    WHERE VARIABLE_NAME IN (
        'max_connections',
        'max_user_connections', 
        'wait_timeout',
        'interactive_timeout',
        'max_allowed_packet',
        'thread_cache_size',
        'table_open_cache',
        'innodb_buffer_pool_size',
        'query_cache_size',
        'tmp_table_size',
        'max_heap_table_size'
    )
    ORDER BY VARIABLE_NAME;" | column -t -s \t'
    echo
}

# تابع اصلی
main() {
    # تشخیص پنل
    PANEL=$(detect_panel)
    
    if [[ "$PANEL" == "unknown" ]]; then
        print_error "Could not detect cPanel or DirectAdmin."
        print_info "Please ensure the server has cPanel or DirectAdmin installed."
        exit 1
    fi
    
    print_success "Detected control panel: $PANEL"
    
    # راه‌اندازی MySQL بر اساس پنل
    if [[ "$PANEL" == "cpanel" ]]; then
        setup_cpanel_mysql || exit 2
    elif [[ "$PANEL" == "directadmin" ]]; then
        setup_da_mysql || exit 2
    fi
    
    print_success "MySQL connection configured (User: $MYSQL_USER)"
    echo
    sleep 1
    
    # حلقه اصلی منو
    while true; do
        show_menu
        read -rp "Select an option [1-18]: " choice
        echo
        
        case $choice in
            1)
                show_top_databases_by_queries
                ;;
            2)
                show_databases_with_longest_queries
                ;;
            3)
                show_databases_by_connections
                ;;
            4)
                show_database_detailed_stats
                ;;
            5)
                show_top_users
                ;;
            6)
                realtime_monitor
                ;;
            7)
                show_server_summary
                ;;
            8)
                read -rp "Enter database name: " dbname
                [[ -z "$dbname" ]] && { print_error "Database name required."; continue; }
                kill_db_queries "$dbname" "Query"
                ;;
            9)
                read -rp "Enter database name (or press Enter for all): " dbname
                show_processlist "$dbname"
                ;;
            10)
                read -rp "Enter minimum time in seconds [default: 60]: " min_time
                min_time="${min_time:-60}"
                kill_long_queries "$min_time"
                ;;
            11)
                read -rp "Enter username: " username
                [[ -z "$username" ]] && { print_error "Username required."; continue; }
                kill_user_queries "$username"
                ;;
            12)
                read -rp "Enter process ID: " pid
                [[ -z "$pid" ]] && { print_error "Process ID required."; continue; }
                kill_specific_process "$pid"
                ;;
            13)
                show_processlist
                ;;
            14)
                read -rp "Enter database name (or press Enter for all): " dbname
                kill_sleeping_connections "$dbname"
                ;;
            15)
                export_report
                ;;
            16)
                check_slow_query_log
                ;;
            17)
                show_mysql_variables
                ;;
            18)
                print_info "Exiting..."
                exit 0
                ;;
            *)
                print_error "Invalid option. Please select 1-18."
                ;;
        esac
        
        echo
        read -rp "Press Enter to continue..."
    done
}

# اجرای برنامه
main\t'
    echo
    
    local count
    count=$(echo "$ids" | grep -c . || echo 0)
    
    print_warning "Kill $count process(es)? (y/n): "
    read -r confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_action "INFO" "Kill long queries aborted by user"
        return 0
    fi
    
    local killed=0
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1 && ((killed++))
    done <<< "$ids"
    
    print_success "Killed $killed process(es)."
    log_kill_action "Kill Long Queries" "Time>${min_time}s" "$killed" "Threshold: ${min_time}s"
}

# کشتن تمام کانکشن‌های Sleep
kill_sleeping_connections() {
    local db="${1:-}"
    
    local where_clause="command='Sleep'"
    [[ -n "$db" ]] && where_clause="$where_clause AND db='$db'"
    where_clause="$where_clause AND user != '${MYSQL_USER}'"
    
    print_info "Searching for sleeping connections..."
    
    local ids
    ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE ${where_clause};" 2>/dev/null || true)
    
    if [[ -z "${ids//[[:space:]]/}" ]]; then
        print_warning "No sleeping connections found."
        return 0
    fi
    
    local count
    count=$(echo "$ids" | grep -c . || echo 0)
    
    print_warning "Found $count sleeping connection(s). Kill them? (y/n): "
    read -r confirm
    
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return 0
    
    local killed=0
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1 && ((killed++))
    done <<< "$ids"
    
    print_success "Killed $killed sleeping connection(s)."
}

# کشتن پروسس‌های یک کاربر
kill_user_queries() {
    local username="$1"
    
    print_info "Searching for processes by user: $username"
    
    local ids
    ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE user='${username}' AND user != '${MYSQL_USER}';" 2>/dev/null || true)
    
    if [[ -z "${ids//[[:space:]]/}" ]]; then
        print_warning "No processes found for user '$username'."
        return 0
    fi
    
    "${MYSQL_CMD[@]}" -e "SELECT id, db, command, time, state FROM information_schema.processlist WHERE user='${username}';" | column -t -s $'\t'
    echo
    
    local count
    count=$(echo "$ids" | grep -c . || echo 0)
    
    print_warning "Kill $count process(es) for user '$username'? (y/n): "
    read -r confirm
    
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return 0
    
    local killed=0
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1 && ((killed++))
    done <<< "$ids"
    
    print_success "Killed $killed process(es)."
}

# کشتن یک پروسس خاص
kill_specific_process() {
    local pid="$1"
    
    local exists
    exists=$("${MYSQL_CMD[@]}" -e "SELECT COUNT(*) FROM information_schema.processlist WHERE id=${pid};" 2>/dev/null || echo "0")
    
    if [[ "$exists" == "0" ]]; then
        print_error "Process ID $pid not found."
        return 1
    fi
    
    print_info "Process details:"
    "${MYSQL_CMD[@]}" -e "SELECT * FROM information_schema.processlist WHERE id=${pid}\\G"
    echo
    
    print_warning "Kill this process? (y/n): "
    read -r confirm
    
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return 0
    
    if "${MYSQL_CMD[@]}" -e "KILL ${pid};" >/dev/null 2>&1; then
        print_success "Process $pid killed successfully."
    else
        print_error "Failed to kill process $pid."
        return 1
    fi
}

# Export گزارش
export_report() {
    local filename="mysql_report_$(date +%Y%m%d_%H%M%S).txt"
    
    print_info "Generating report..."
    
    {
        echo "======================================================================"
        echo "MySQL Server Report"
        echo "Generated: $(date)"
        echo "======================================================================"
        echo
        
        echo "=== Server Summary ==="
        "${MYSQL_CMD[@]}" -e "
        SELECT VARIABLE_NAME, VARIABLE_VALUE 
        FROM information_schema.GLOBAL_STATUS 
        WHERE VARIABLE_NAME IN ('Uptime', 'Threads_connected', 'Threads_running', 'Questions', 'Queries');" | column -t -s $'\t'
        echo
        
        echo "=== TOP Databases by Query Count ==="
        "${MYSQL_CMD[@]}" -e "
        SELECT COALESCE(db, 'NULL') as database_name, COUNT(*) as count
        FROM information_schema.processlist
        WHERE user != '${MYSQL_USER}'
        GROUP BY db ORDER BY count DESC LIMIT 20;" | column -t -s $'\t'
        echo
        
        echo "=== Active Processes ==="
        "${MYSQL_CMD[@]}" -e "
        SELECT id, user, db, command, time, state, LEFT(info, 100)
        FROM information_schema.processlist
        ORDER BY time DESC;" | column -t -s $'\t'
        
    } > "$filename"
    
    print_success "Report saved to: $filename"
}

# بررسی Slow Query Log
check_slow_query_log() {
    print_header "Slow Query Log Status"
    
    "${MYSQL_CMD[@]}" -e "
    SELECT VARIABLE_NAME, VARIABLE_VALUE 
    FROM information_schema.GLOBAL_VARIABLES 
    WHERE VARIABLE_NAME IN ('slow_query_log', 'slow_query_log_file', 'long_query_time');" | column -t -s $'\t'
    echo
    
    local log_enabled
    log_enabled=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_VARIABLES WHERE VARIABLE_NAME='slow_query_log';")
    
    if [[ "$log_enabled" == "ON" ]]; then
        print_success "Slow query log is enabled"
        local log_file
        log_file=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_VARIABLES WHERE VARIABLE_NAME='slow_query_log_file';")
        
        if [[ -f "$log_file" ]]; then
            print_info "Log file: $log_file"
            print_info "Last 10 entries:"
            tail -n 20 "$log_file" 2>/dev/null || print_warning "Cannot read log file"
        fi
    else
        print_warning "Slow query log is disabled"
        print_info "To enable: SET GLOBAL slow_query_log = 'ON';"
    fi
}

# نمایش MySQL Variables
show_mysql_variables() {
    print_header "Important MySQL Variables"
    
    "${MYSQL_CMD[@]}" -e "
    SELECT VARIABLE_NAME, VARIABLE_VALUE 
    FROM information_schema.GLOBAL_VARIABLES 
    WHERE VARIABLE_NAME IN (
        'max_connections',
        'max_user_connections', 
        'wait_timeout',
        'interactive_timeout',
        'max_allowed_packet',
        'thread_cache_size',
        'table_open_cache',
        'innodb_buffer_pool_size',
        'query_cache_size',
        'tmp_table_size',
        'max_heap_table_size'
    )
    ORDER BY VARIABLE_NAME;" | column -t -s \t'
    echo
}

# تابع اصلی
main() {
    # تشخیص پنل
    PANEL=$(detect_panel)
    
    if [[ "$PANEL" == "unknown" ]]; then
        print_error "Could not detect cPanel or DirectAdmin."
        print_info "Please ensure the server has cPanel or DirectAdmin installed."
        exit 1
    fi
    
    print_success "Detected control panel: $PANEL"
    
    # راه‌اندازی MySQL بر اساس پنل
    if [[ "$PANEL" == "cpanel" ]]; then
        setup_cpanel_mysql || exit 2
    elif [[ "$PANEL" == "directadmin" ]]; then
        setup_da_mysql || exit 2
    fi
    
    print_success "MySQL connection configured (User: $MYSQL_USER)"
    echo
    sleep 1
    
    # حلقه اصلی منو
    while true; do
        show_menu
        read -rp "Select an option [1-18]: " choice
        echo
        
        case $choice in
            1)
                show_top_databases_by_queries
                ;;
            2)
                show_databases_with_longest_queries
                ;;
            3)
                show_databases_by_connections
                ;;
            4)
                show_database_detailed_stats
                ;;
            5)
                show_top_users
                ;;
            6)
                realtime_monitor
                ;;
            7)
                show_server_summary
                ;;
            8)
                read -rp "Enter database name: " dbname
                [[ -z "$dbname" ]] && { print_error "Database name required."; continue; }
                kill_db_queries "$dbname" "Query"
                ;;
            9)
                read -rp "Enter database name (or press Enter for all): " dbname
                show_processlist "$dbname"
                ;;
            10)
                read -rp "Enter minimum time in seconds [default: 60]: " min_time
                min_time="${min_time:-60}"
                kill_long_queries "$min_time"
                ;;
            11)
                read -rp "Enter username: " username
                [[ -z "$username" ]] && { print_error "Username required."; continue; }
                kill_user_queries "$username"
                ;;
            12)
                read -rp "Enter process ID: " pid
                [[ -z "$pid" ]] && { print_error "Process ID required."; continue; }
                kill_specific_process "$pid"
                ;;
            13)
                show_processlist
                ;;
            14)
                read -rp "Enter database name (or press Enter for all): " dbname
                kill_sleeping_connections "$dbname"
                ;;
            15)
                export_report
                ;;
            16)
                check_slow_query_log
                ;;
            17)
                show_mysql_variables
                ;;
            18)
                print_info "Exiting..."
                exit 0
                ;;
            *)
                print_error "Invalid option. Please select 1-18."
                ;;
        esac
        
        echo
        read -rp "Press Enter to continue..."
    done
}

# اجرای برنامه
main
