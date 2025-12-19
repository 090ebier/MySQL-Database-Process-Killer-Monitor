#!/usr/bin/env bash
#
# MySQL Database Process Killer & Monitor
# Compatible with cPanel and DirectAdmin
# Version: 4.0 - Bug Fixed & Enhanced
#
# CHANGELOG v4.0:
# - Fixed duplicate function definitions
# - Fixed incomplete export_report function
# - Fixed string concatenation issues in SQL queries
# - Improved error handling and validation
# - Enhanced security measures
# - Better code organization
# - All text translated to English
#

set -euo pipefail
IFS=$'\n\t'

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# Configuration
readonly LOG_DIR="/var/log/mysql_killer"
LOG_FILE="${LOG_DIR}/mysql_killer.log"
readonly MAX_LOG_SIZE=10485760  # 10MB

# MySQL connection variables
declare -a MYSQL_CMD
MYSQL_USER=""
TMP_CNF=""

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

log_action() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [[ "$LOG_FILE" != "/dev/null" ]] && [[ -w "$LOG_FILE" ]]; then
        echo "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE" 2>/dev/null || true
        
        # Rotate log if too large
        if [[ -f "$LOG_FILE" ]]; then
            local size
            size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
            if [[ $size -gt $MAX_LOG_SIZE ]]; then
                mv "$LOG_FILE" "${LOG_FILE}.old" 2>/dev/null || true
                touch "$LOG_FILE"
                chmod 600 "$LOG_FILE" 2>/dev/null || true
            fi
        fi
    fi
}

log_kill_action() {
    local action="$1" target="$2" count="$3" details="${4:-}"
    log_action "KILL" "Action: ${action} | Target: ${target} | Count: ${count} | Details: ${details}"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    log_action "ERROR" "$1"
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
    echo -e "${CYAN}${BOLD}║  $1${NC}"
    echo -e "${CYAN}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Sanitize input - remove dangerous characters
sanitize_input() {
    local input="$1"
    echo "$input" | sed 's/[^a-zA-Z0-9_.-]//g' | head -c 64
}

# SQL escape - prevent SQL injection
sql_escape() {
    local input="$1"
    printf '%s' "$input" | sed "s/'/''/g"
}

# Validate numeric input
validate_number() {
    local input="$1"
    if [[ "$input" =~ ^[0-9]+$ ]]; then
        echo "$input"
    else
        echo "0"
    fi
}

# Initialize logging
init_logging() {
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR" 2>/dev/null || {
            LOG_DIR="/root/mysql_killer_logs"
            LOG_FILE="${LOG_DIR}/mysql_killer.log"
            mkdir -p "$LOG_DIR" 2>/dev/null || {
                LOG_FILE="/dev/null"
                return 1
            }
        }
    fi
    
    touch "$LOG_FILE" 2>/dev/null || {
        LOG_FILE="/dev/null"
        return 1
    }
    
    chmod 600 "$LOG_FILE" 2>/dev/null || true
    return 0
}

# Cleanup on exit
cleanup() {
    if [[ -n "${TMP_CNF:-}" && -f "$TMP_CNF" ]]; then
        shred -u "$TMP_CNF" 2>/dev/null || rm -f "$TMP_CNF"
    fi
}
trap cleanup EXIT INT TERM

# ============================================================================
# CONTROL PANEL DETECTION AND MYSQL SETUP
# ============================================================================

detect_panel() {
    if [[ -f /usr/local/cpanel/cpanel ]] || [[ -d /var/cpanel ]]; then
        echo "cpanel"
    elif [[ -f /usr/local/directadmin/directadmin ]] || [[ -f /usr/local/directadmin/conf/mysql.conf ]]; then
        echo "directadmin"
    else
        echo "unknown"
    fi
}

setup_cpanel_mysql() {
    local cnf_file
    
    if [[ -f /root/.my.cnf ]]; then
        cnf_file="/root/.my.cnf"
    elif [[ -f /root/my.cnf ]]; then
        cnf_file="/root/my.cnf"
    else
        print_error "Neither /root/.my.cnf nor /root/my.cnf found."
        return 1
    fi
    
    MYSQL_CMD=(mysql --batch --skip-column-names --defaults-extra-file="$cnf_file" --connect-timeout=5)
    MYSQL_USER="root"
    
    if ! "${MYSQL_CMD[@]}" -e "SELECT 1;" >/dev/null 2>&1; then
        print_error "Failed to connect to MySQL with cPanel credentials"
        return 1
    fi
    
    return 0
}

setup_da_mysql() {
    local da_conf="/usr/local/directadmin/conf/mysql.conf"
    
    if [[ ! -f "$da_conf" ]]; then
        print_error "DirectAdmin mysql.conf not found at $da_conf"
        return 1
    fi
    
    local da_user da_pass da_socket
    da_user=$(awk -F= '/^user[[:space:]]*=/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$da_conf")
    da_pass=$(awk -F= '/^(passwd|password)[[:space:]]*=/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$da_conf")
    da_socket=$(awk -F= '/^socket[[:space:]]*=/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$da_conf")
    
    [[ -z "$da_user" ]] && da_user="da_admin"
    
    if [[ -z "$da_pass" ]]; then
        print_error "Could not read MySQL password from $da_conf"
        return 1
    fi
    
    # Create secure temporary config file (FIXED: No password in process list)
    TMP_CNF=$(mktemp -t mysql_config.XXXXXX 2>/dev/null || mktemp /tmp/mysql_config.XXXXXX)
    chmod 600 "$TMP_CNF"
    
    cat > "$TMP_CNF" <<EOF
[client]
user=${da_user}
password=${da_pass}
EOF
    
    if [[ -n "$da_socket" && -S "$da_socket" ]]; then
        echo "socket=${da_socket}" >> "$TMP_CNF"
    fi
    
    MYSQL_CMD=(mysql --batch --skip-column-names --defaults-extra-file="$TMP_CNF" --connect-timeout=5)
    MYSQL_USER="$da_user"
    
    if ! "${MYSQL_CMD[@]}" -e "SELECT 1;" >/dev/null 2>&1; then
        print_error "Failed to connect to MySQL with DirectAdmin credentials"
        return 1
    fi
    
    return 0
}

# ============================================================================
# MENU SYSTEM
# ============================================================================

show_menu() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   MySQL Database Process Killer & Monitor v4.0            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${MAGENTA}${BOLD}📊 Monitoring & Analysis:${NC}"
    echo "  1) 🔥 Show TOP databases by query count"
    echo "  2) ⏱️  Show databases with longest queries"
    echo "  3) 💾 Show databases by connection count"
    echo "  4) 📈 Show detailed database statistics"
    echo "  5) 👥 Show TOP users by resource usage"
    echo "  6) 🔍 Real-time process monitor"
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

# ============================================================================
# MONITORING FUNCTIONS
# ============================================================================

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
        COUNT(DISTINCT user) as user_count
    FROM information_schema.processlist
    WHERE user != '$(sql_escape "$MYSQL_USER")'
    GROUP BY db
    ORDER BY active_queries DESC, query_count DESC
    LIMIT 20;
    "
    
    echo -e "${BOLD}Database Name         | Total | Active | Sleep | Avg(s) | Max(s) | Users${NC}"
    echo "─────────────────────────────────────────────────────────────────────────────"
    
    "${MYSQL_CMD[@]}" -e "$query" 2>/dev/null | while IFS=$'\t' read -r db count active sleep avg_t max_t users; do
        local color="${GREEN}"
        [[ ${active:-0} -gt 5 ]] && color="${CYAN}"
        [[ ${active:-0} -gt 20 ]] && color="${YELLOW}"
        [[ ${active:-0} -gt 50 ]] && color="${RED}${BOLD}"
        
        printf "${color}%-22s${NC}| %-5s | ${color}%-6s${NC} | %-5s | %-6s | %-6s | %s\n" \
            "${db:0:22}" "${count:-0}" "${active:-0}" "${sleep:-0}" "${avg_t:-0}" "${max_t:-0}" "${users:-0}"
    done
    
    echo
    print_info "Legend: ${RED}Critical (>50)${NC} | ${YELLOW}High (>20)${NC} | ${CYAN}Medium (>5)${NC} | ${GREEN}Normal${NC}"
}

show_databases_with_longest_queries() {
    print_header "Databases with Longest Running Queries"
    
    local query="
    SELECT 
        COALESCE(db, 'NULL') as database_name,
        MAX(time) as longest_query,
        user,
        COALESCE(state, 'NULL') as state,
        LEFT(COALESCE(info, 'NULL'), 60) as query_sample
    FROM information_schema.processlist
    WHERE command='Query' AND user != '$(sql_escape "$MYSQL_USER")' AND time > 0
    GROUP BY db, user, state, info
    ORDER BY longest_query DESC
    LIMIT 20;
    "
    
    echo -e "${BOLD}Time(s) | Database             | User            | State                | Query${NC}"
    echo "────────────────────────────────────────────────────────────────────────────────────"
    
    "${MYSQL_CMD[@]}" -e "$query" 2>/dev/null | while IFS=$'\t' read -r db time user state query_text; do
        local color="${CYAN}"
        [[ ${time:-0} -gt 60 ]] && color="${YELLOW}"
        [[ ${time:-0} -gt 300 ]] && color="${RED}${BOLD}"
        
        printf "${color}%-7s${NC} | %-20s | %-15s | %-20s | %s\n" \
            "${time:-0}" "${db:0:20}" "${user:0:15}" "${state:0:20}" "${query_text:0:40}"
    done
    
    echo
    print_info "Queries: ${RED}>300s = Critical${NC} | ${YELLOW}>60s = Warning${NC}"
}

show_databases_by_connections() {
    print_header "Databases by Connection Count"
    
    local query="
    SELECT 
        COALESCE(db, 'NULL') as database_name,
        COUNT(DISTINCT id) as total_connections,
        COUNT(DISTINCT user) as unique_users,
        SUM(CASE WHEN command='Sleep' THEN 1 ELSE 0 END) as idle_connections
    FROM information_schema.processlist
    WHERE user != '$(sql_escape "$MYSQL_USER")'
    GROUP BY db
    ORDER BY total_connections DESC
    LIMIT 20;
    "
    
    echo -e "${BOLD}Database              | Connections | Users | Idle${NC}"
    echo "────────────────────────────────────────────────────────────"
    
    "${MYSQL_CMD[@]}" -e "$query" 2>/dev/null | while IFS=$'\t' read -r db conns users idle; do
        local color="${GREEN}"
        [[ ${conns:-0} -gt 50 ]] && color="${YELLOW}"
        [[ ${conns:-0} -gt 100 ]] && color="${RED}${BOLD}"
        
        printf "${color}%-22s${NC}| ${color}%-11s${NC} | %-5s | %s\n" \
            "${db:0:22}" "${conns:-0}" "${users:-0}" "${idle:-0}"
    done
    
    echo
}

show_database_detailed_stats() {
    read -rp "Enter database name: " dbname
    [[ -z "$dbname" ]] && { print_error "Database name required."; return; }
    
    dbname=$(sanitize_input "$dbname")
    print_header "Detailed Statistics: $dbname"
    
    local stats
    stats=$("${MYSQL_CMD[@]}" -e "
    SELECT 
        COALESCE(COUNT(*), 0),
        COALESCE(SUM(CASE WHEN command='Sleep' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN command='Query' THEN 1 ELSE 0 END), 0),
        COALESCE(MAX(time), 0),
        COALESCE(ROUND(AVG(time), 2), 0)
    FROM information_schema.processlist
    WHERE db='$(sql_escape "$dbname")';
    " 2>/dev/null)
    
    read -r total sleeping active max_t avg_t <<< "$stats"
    
    echo -e "${CYAN}Overview:${NC}"
    echo -e "  Total Processes: ${BOLD}${total:-0}${NC}"
    echo -e "  Active Queries:  ${BOLD}${active:-0}${NC}"
    echo -e "  Sleeping:        ${BOLD}${sleeping:-0}${NC}"
    echo -e "  Max Query Time:  ${BOLD}${max_t:-0}s${NC}"
    echo -e "  Avg Query Time:  ${BOLD}${avg_t:-0}s${NC}"
    echo
    
    echo -e "${CYAN}Users:${NC}"
    "${MYSQL_CMD[@]}" -e "
    SELECT user, COUNT(*) as connections
    FROM information_schema.processlist
    WHERE db='$(sql_escape "$dbname")'
    GROUP BY user;
    " 2>/dev/null | column -t -s $'\t' || echo "  No active users"
    echo
    
    echo -e "${CYAN}Top 5 Longest Queries:${NC}"
    "${MYSQL_CMD[@]}" -e "
    SELECT id, user, time, LEFT(COALESCE(info, 'NULL'), 80) as query
    FROM information_schema.processlist
    WHERE db='$(sql_escape "$dbname")' AND command='Query'
    ORDER BY time DESC
    LIMIT 5;
    " 2>/dev/null | column -t -s $'\t' || echo "  No active queries"
    echo
}

show_top_users() {
    print_header "TOP Users by Resource Usage"
    
    local query="
    SELECT 
        user,
        COUNT(*) as total,
        SUM(CASE WHEN command='Query' THEN 1 ELSE 0 END) as active,
        SUM(CASE WHEN command='Sleep' THEN 1 ELSE 0 END) as sleeping,
        ROUND(AVG(time), 2) as avg_time,
        MAX(time) as max_time,
        COUNT(DISTINCT db) as dbs
    FROM information_schema.processlist
    WHERE user != '$(sql_escape "$MYSQL_USER")' AND user != 'system user'
    GROUP BY user
    ORDER BY active DESC, total DESC
    LIMIT 15;
    "
    
    echo -e "${BOLD}User                 | Total | Active | Sleep | Avg(s) | Max(s) | DBs${NC}"
    echo "────────────────────────────────────────────────────────────────────────────"
    
    "${MYSQL_CMD[@]}" -e "$query" 2>/dev/null | while IFS=$'\t' read -r user total active sleep avg_t max_t dbs; do
        local color="${GREEN}"
        [[ ${active:-0} -gt 10 ]] && color="${YELLOW}"
        [[ ${active:-0} -gt 20 ]] && color="${RED}${BOLD}"
        
        printf "${color}%-21s${NC}| %-5s | ${color}%-6s${NC} | %-5s | %-6s | %-6s | %s\n" \
            "${user:0:21}" "${total:-0}" "${active:-0}" "${sleep:-0}" "${avg_t:-0}" "${max_t:-0}" "${dbs:-0}"
    done
    
    echo
}

realtime_monitor() {
    local refresh_rate=3
    read -rp "Refresh interval in seconds [default: 3]: " input_rate
    
    if [[ -n "$input_rate" ]] && [[ "$input_rate" =~ ^[0-9]+$ ]] && [[ $input_rate -gt 0 ]]; then
        refresh_rate=$input_rate
    fi
    
    print_info "Starting monitor (refresh: ${refresh_rate}s). Press Ctrl+C to stop..."
    sleep 1
    
    while true; do
        clear
        print_header "Real-Time Monitor - $(date '+%H:%M:%S')"
        
        local stats
        stats=$("${MYSQL_CMD[@]}" -e "
        SELECT 
            COUNT(*),
            SUM(CASE WHEN command='Query' THEN 1 ELSE 0 END),
            SUM(CASE WHEN command='Sleep' THEN 1 ELSE 0 END),
            MAX(time)
        FROM information_schema.processlist;
        " 2>/dev/null || echo "0 0 0 0")
        
        read -r total active sleeping max_t <<< "$stats"
        
        echo -e "${BOLD}Summary:${NC} Total: ${total:-0} | Active: ${YELLOW}${active:-0}${NC} | Sleep: ${sleeping:-0} | Max: ${RED}${max_t:-0}s${NC}"
        echo
        
        echo -e "${BOLD}TOP 15 Active Queries:${NC}"
        echo "─────────────────────────────────────────────────────────────────────────"
        "${MYSQL_CMD[@]}" -e "
        SELECT id, user, COALESCE(db,'NULL') as db, time, LEFT(COALESCE(info,'NULL'), 50)
        FROM information_schema.processlist
        WHERE command='Query' AND user != '$(sql_escape "$MYSQL_USER")'
        ORDER BY time DESC
        LIMIT 15;
        " 2>/dev/null | column -t -s $'\t'
        
        sleep "$refresh_rate"
    done
}

show_server_summary() {
    print_header "Server Load Summary"
    
    echo -e "${CYAN}${BOLD}MySQL Status:${NC}"
    local uptime threads_conn threads_run queries
    while IFS=$'\t' read -r name value; do
        case "$name" in
            Uptime) uptime=$value ;;
            Threads_connected) threads_conn=$value ;;
            Threads_running) threads_run=$value ;;
            Queries) queries=$value ;;
        esac
    done < <("${MYSQL_CMD[@]}" -e "
    SELECT VARIABLE_NAME, VARIABLE_VALUE 
    FROM information_schema.GLOBAL_STATUS 
    WHERE VARIABLE_NAME IN ('Uptime','Threads_connected','Threads_running','Queries');
    " 2>/dev/null)
    
    local uptime_hrs=$(( ${uptime:-0} / 3600 ))
    echo -e "  Uptime:            ${BOLD}${uptime_hrs}h${NC}"
    echo -e "  Threads Connected: ${BOLD}${threads_conn:-0}${NC}"
    echo -e "  Threads Running:   ${BOLD}${threads_run:-0}${NC}"
    echo -e "  Total Queries:     ${BOLD}${queries:-0}${NC}"
    echo
    
    echo -e "${CYAN}${BOLD}Process Summary:${NC}"
    "${MYSQL_CMD[@]}" -e "
    SELECT command, COUNT(*) as count, ROUND(AVG(time),2) as avg_t, MAX(time) as max_t
    FROM information_schema.processlist
    GROUP BY command
    ORDER BY count DESC;
    " 2>/dev/null | column -t -s $'\t'
    echo
    
    if command -v uptime &> /dev/null; then
        echo -e "${CYAN}${BOLD}System Load:${NC}"
        uptime
        echo
    fi
}

show_processlist() {
    local db="${1:-}"
    local where=""
    
    if [[ -n "$db" ]]; then
        db=$(sanitize_input "$db")
        where="WHERE db='$(sql_escape "$db")'"
    fi
    
    print_info "Active processes:"
    echo
    "${MYSQL_CMD[@]}" -e "
    SELECT id, user, COALESCE(db,'NULL') as db, command, time, COALESCE(state,'NULL'), LEFT(COALESCE(info,'NULL'), 40)
    FROM information_schema.processlist
    $where
    ORDER BY time DESC;
    " 2>/dev/null | column -t -s $'\t'
    echo
}

# ============================================================================
# KILL OPERATIONS
# ============================================================================

kill_db_queries() {
    local db="$1"
    local cmd="${2:-Query}"
    
    db=$(sanitize_input "$db")
    cmd=$(sanitize_input "$cmd")
    
    print_info "Searching: DB='$db', Command='$cmd'"
    log_action "INFO" "Kill search: DB=$db, Cmd=$cmd"
    
    local ids
    ids=$("${MYSQL_CMD[@]}" -e "
    SELECT id FROM information_schema.processlist 
    WHERE db='$(sql_escape "$db")' 
      AND command='$(sql_escape "$cmd")' 
      AND user != '$(sql_escape "$MYSQL_USER")';
    " 2>/dev/null)
    
    [[ -z "${ids//[[:space:]]/}" ]] && { print_warning "No processes found."; return 0; }
    
    local count=$(echo "$ids" | grep -c ^ || echo 0)
    print_warning "Found $count process(es). Kill? (y/n): "
    read -r confirm
    
    [[ "$confirm" != "y" ]] && [[ "$confirm" != "Y" ]] && { print_info "Aborted."; return 0; }
    
    local killed=0 failed=0
    while IFS= read -r id; do
        [[ -z "$id" || ! "$id" =~ ^[0-9]+$ ]] && continue
        
        if "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1; then
            ((killed++))
            echo -ne "\r${GREEN}[✓]${NC} Killed: $killed/$count"
        else
            ((failed++))
        fi
    done <<< "$ids"
    
    echo
    print_success "Killed: $killed, Failed: $failed"
    log_kill_action "Kill DB" "$db" "$killed" "Cmd=$cmd, Failed=$failed"
}

kill_long_queries() {
    local min_time="${1:-60}"
    min_time=$(validate_number "$min_time")
    [[ $min_time -eq 0 ]] && min_time=60
    
    print_info "Searching queries >$min_time seconds..."
    
    local ids
    ids=$("${MYSQL_CMD[@]}" -e "
    SELECT id FROM information_schema.processlist 
    WHERE command='Query' AND time > $min_time 
      AND user != '$(sql_escape "$MYSQL_USER")';
    " 2>/dev/null)
    
    [[ -z "${ids//[[:space:]]/}" ]] && { print_warning "No long queries found."; return 0; }
    
    print_info "Long-running queries:"
    "${MYSQL_CMD[@]}" -e "
    SELECT id, user, COALESCE(db,'NULL'), time, LEFT(COALESCE(info,'NULL'), 60)
    FROM information_schema.processlist
    WHERE command='Query' AND time > $min_time 
      AND user != '$(sql_escape "$MYSQL_USER")';
    " 2>/dev/null | column -t -s $'\t'
    echo
    
    local count=$(echo "$ids" | grep -c ^ || echo 0)
    print_warning "Kill $count process(es)? (y/n): "
    read -r confirm
    
    [[ "$confirm" != "y" ]] && [[ "$confirm" != "Y" ]] && return 0
    
    local killed=0
    while IFS= read -r id; do
        [[ -z "$id" || ! "$id" =~ ^[0-9]+$ ]] && continue
        "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1 && ((killed++))
    done <<< "$ids"
    
    print_success "Killed: $killed"
    log_kill_action "Kill Long" ">$min_time"s "$killed"
}

kill_sleeping_connections() {
    local db="${1:-}"
    local where="command='Sleep' AND user != '$(sql_escape "$MYSQL_USER")'"
    
    if [[ -n "$db" ]]; then
        db=$(sanitize_input "$db")
        where="$where AND db='$(sql_escape "$db")'"
    fi
    
    local ids
    ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE $where;" 2>/dev/null)
    
    [[ -z "${ids//[[:space:]]/}" ]] && { print_warning "No sleeping connections."; return 0; }
    
    local count=$(echo "$ids" | grep -c ^ || echo 0)
    print_warning "Kill $count sleeping connection(s)? (y/n): "
    read -r confirm
    
    [[ "$confirm" != "y" ]] && [[ "$confirm" != "Y" ]] && return 0
    
    local killed=0
    while IFS= read -r id; do
        [[ -z "$id" || ! "$id" =~ ^[0-9]+$ ]] && continue
        "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1 && ((killed++))
    done <<< "$ids"
    
    print_success "Killed: $killed"
    log_kill_action "Kill Sleep" "${db:-all}" "$killed"
}

kill_user_queries() {
    local username="$1"
    username=$(sanitize_input "$username")
    
    print_info "Searching processes: user='$username'"
    
    local ids
    ids=$("${MYSQL_CMD[@]}" -e "
    SELECT id FROM information_schema.processlist 
    WHERE user='$(sql_escape "$username")' 
      AND user != '$(sql_escape "$MYSQL_USER")';
    " 2>/dev/null)
    
    [[ -z "${ids//[[:space:]]/}" ]] && { print_warning "No processes found."; return 0; }
    
    "${MYSQL_CMD[@]}" -e "
    SELECT id, COALESCE(db,'NULL'), command, time, COALESCE(state,'NULL')
    FROM information_schema.processlist
    WHERE user='$(sql_escape "$username")';
    " 2>/dev/null | column -t -s \t'
    echo
    
    local count=$(echo "$ids" | grep -c ^ || echo 0)
    print_warning "Kill $count process(es)? (y/n): "
    read -r confirm
    
    [[ "$confirm" != "y" ]] && [[ "$confirm" != "Y" ]] && return 0
    
    local killed=0
    while IFS= read -r id; do
        [[ -z "$id" || ! "$id" =~ ^[0-9]+$ ]] && continue
        "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1 && ((killed++))
    done <<< "$ids"
    
    print_success "Killed: $killed"
    log_kill_action "Kill User" "$username" "$killed"
}

kill_specific_process() {
    local pid="$1"
    pid=$(validate_number "$pid")
    
    [[ $pid -eq 0 ]] && { print_error "Invalid process ID."; return 1; }
    
    local exists
    exists=$("${MYSQL_CMD[@]}" -e "SELECT COUNT(*) FROM information_schema.processlist WHERE id=$pid;" 2>/dev/null)
    
    [[ "$exists" == "0" ]] && { print_error "Process $pid not found."; return 1; }
    
    print_info "Process details:"
    "${MYSQL_CMD[@]}" -e "SELECT * FROM information_schema.processlist WHERE id=$pid\\G"
    echo
    
    print_warning "Kill this process? (y/n): "
    read -r confirm
    
    [[ "$confirm" != "y" ]] && [[ "$confirm" != "Y" ]] && return 0
    
    if "${MYSQL_CMD[@]}" -e "KILL $pid;" >/dev/null 2>&1; then
        print_success "Process $pid killed."
        log_kill_action "Kill PID" "$pid" "1"
    else
        print_error "Failed to kill process $pid."
        return 1
    fi
}

# ============================================================================
# ADVANCED FUNCTIONS
# ============================================================================

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
        WHERE VARIABLE_NAME IN ('Uptime','Threads_connected','Threads_running','Queries');" 2>/dev/null | column -t -s \t'
        echo
        
        echo "=== TOP Databases ==="
        "${MYSQL_CMD[@]}" -e "
        SELECT COALESCE(db,'NULL'), COUNT(*) 
        FROM information_schema.processlist
        WHERE user != '$(sql_escape "$MYSQL_USER")'
        GROUP BY db ORDER BY COUNT(*) DESC LIMIT 20;" 2>/dev/null | column -t -s \t'
        echo
        
        echo "=== Active Processes ==="
        "${MYSQL_CMD[@]}" -e "
        SELECT id, user, COALESCE(db,'NULL'), command, time, LEFT(COALESCE(info,'NULL'), 80)
        FROM information_schema.processlist
        ORDER BY time DESC;" 2>/dev/null | column -t -s \t'
        
    } > "$filename" 2>/dev/null
    
    if [[ -f "$filename" ]]; then
        print_success "Report saved: $filename"
        log_action "INFO" "Report exported: $filename"
    else
        print_error "Failed to create report"
    fi
}

check_slow_query_log() {
    print_header "Slow Query Log Status"
    
    "${MYSQL_CMD[@]}" -e "
    SELECT VARIABLE_NAME, VARIABLE_VALUE 
    FROM information_schema.GLOBAL_VARIABLES 
    WHERE VARIABLE_NAME IN ('slow_query_log','slow_query_log_file','long_query_time');" 2>/dev/null | column -t -s \t'
    echo
    
    local enabled
    enabled=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_VARIABLES WHERE VARIABLE_NAME='slow_query_log';" 2>/dev/null)
    
    if [[ "$enabled" == "ON" ]]; then
        print_success "Slow query log enabled"
        
        local logfile
        logfile=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_VARIABLES WHERE VARIABLE_NAME='slow_query_log_file';" 2>/dev/null)
        
        if [[ -f "$logfile" ]] && [[ -r "$logfile" ]]; then
            print_info "Log file: $logfile"
            print_info "Last 10 entries:"
            tail -n 20 "$logfile" 2>/dev/null || print_warning "Cannot read log"
        fi
    else
        print_warning "Slow query log disabled"
        print_info "To enable: SET GLOBAL slow_query_log = 'ON';"
    fi
}

show_mysql_variables() {
    print_header "Important MySQL Variables"
    
    "${MYSQL_CMD[@]}" -e "
    SELECT VARIABLE_NAME, VARIABLE_VALUE 
    FROM information_schema.GLOBAL_VARIABLES 
    WHERE VARIABLE_NAME IN (
        'max_connections','max_user_connections','wait_timeout',
        'interactive_timeout','max_allowed_packet','thread_cache_size',
        'table_open_cache','innodb_buffer_pool_size','tmp_table_size'
    )
    ORDER BY VARIABLE_NAME;" 2>/dev/null | column -t -s \t'
    echo
}

view_logs() {
    print_header "Operation Logs"
    
    if [[ ! -f "$LOG_FILE" ]] || [[ "$LOG_FILE" == "/dev/null" ]]; then
        print_warning "No log file available."
        return
    fi
    
    local lines
    lines=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)
    
    print_info "Log file: $LOG_FILE"
    print_info "Total lines: $lines"
    echo
    
    [[ $lines -eq 0 ]] && { print_warning "Log is empty."; return; }
    
    read -rp "Show last N lines [default: 50]: " show_lines
    show_lines="${show_lines:-50}"
    show_lines=$(validate_number "$show_lines")
    [[ $show_lines -eq 0 ]] && show_lines=50
    
    echo -e "${CYAN}Last ${show_lines} entries:${NC}"
    echo "─────────────────────────────────────────────────────────────"
    
    tail -n "$show_lines" "$LOG_FILE" | while IFS= read -r line; do
        if [[ "$line" =~ ERROR ]]; then
            echo -e "${RED}${line}${NC}"
        elif [[ "$line" =~ WARNING ]]; then
            echo -e "${YELLOW}${line}${NC}"
        elif [[ "$line" =~ KILL ]]; then
            echo -e "${MAGENTA}${line}${NC}"
        else
            echo "$line"
        fi
    done
    echo
    
    echo -e "${CYAN}Statistics:${NC}"
    local kills warns errors
    kills=$(grep -c "\[KILL\]" "$LOG_FILE" 2>/dev/null || echo 0)
    warns=$(grep -c "\[WARNING\]" "$LOG_FILE" 2>/dev/null || echo 0)
    errors=$(grep -c "\[ERROR\]" "$LOG_FILE" 2>/dev/null || echo 0)
    
    echo "  Kill Operations: ${BOLD}$kills${NC}"
    echo "  Warnings: ${YELLOW}$warns${NC}"
    echo "  Errors: ${RED}$errors${NC}"
    echo
}

clear_old_logs() {
    if [[ ! -f "$LOG_FILE" ]] || [[ "$LOG_FILE" == "/dev/null" ]]; then
        print_warning "No log file to clear."
        return
    fi
    
    local size
    size=$(du -h "$LOG_FILE" 2>/dev/null | cut -f1)
    
    print_warning "Current log size: $size"
    print_warning "Clear all logs? (y/n): "
    read -r confirm
    
    if [[ "$confirm" == "y" ]] || [[ "$confirm" == "Y" ]]; then
        > "$LOG_FILE"
        print_success "Logs cleared."
        log_action "INFO" "Logs cleared by user"
    else
        print_info "Cancelled."
    fi
}

# ============================================================================
# MAIN FUNCTION
# ============================================================================

main() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
    
    init_logging
    
    if [[ "$LOG_FILE" != "/dev/null" ]]; then
        print_success "Logging enabled: $LOG_FILE"
    else
        print_warning "Logging disabled (no write access)"
    fi
    
    log_action "INFO" "========== Script Started =========="
    
    # Detect panel
    local panel
    panel=$(detect_panel)
    
    if [[ "$panel" == "unknown" ]]; then
        print_error "Could not detect cPanel or DirectAdmin"
        print_info "Ensure cPanel or DirectAdmin is installed"
        exit 1
    fi
    
    print_success "Detected: $panel"
    log_action "INFO" "Panel: $panel"
    
    # Setup MySQL
    if [[ "$panel" == "cpanel" ]]; then
        setup_cpanel_mysql || exit 2
    elif [[ "$panel" == "directadmin" ]]; then
        setup_da_mysql || exit 2
    fi
    
    print_success "MySQL connected (User: $MYSQL_USER)"
    log_action "INFO" "MySQL connected: $MYSQL_USER"
    echo
    sleep 1
    
    # Main menu loop
    while true; do
        show_menu
        read -rp "Select option [1-20]: " choice
        echo
        
        case "$choice" in
            1) show_top_databases_by_queries ;;
            2) show_databases_with_longest_queries ;;
            3) show_databases_by_connections ;;
            4) show_database_detailed_stats ;;
            5) show_top_users ;;
            6) realtime_monitor ;;
            7) show_server_summary ;;
            8)
                read -rp "Enter database name: " db
                [[ -z "$db" ]] && { print_error "Database name required."; continue; }
                kill_db_queries "$db" "Query"
                ;;
            9)
                read -rp "Enter database name (or Enter for all): " db
                show_processlist "$db"
                ;;
            10)
                read -rp "Minimum time in seconds [default: 60]: " time
                kill_long_queries "${time:-60}"
                ;;
            11)
                read -rp "Enter username: " user
                [[ -z "$user" ]] && { print_error "Username required."; continue; }
                kill_user_queries "$user"
                ;;
            12)
                read -rp "Enter process ID: " pid
                [[ -z "$pid" ]] && { print_error "Process ID required."; continue; }
                kill_specific_process "$pid"
                ;;
            13) show_processlist ;;
            14)
                read -rp "Database name (or Enter for all): " db
                kill_sleeping_connections "$db"
                ;;
            15) export_report ;;
            16) check_slow_query_log ;;
            17) show_mysql_variables ;;
            18) view_logs ;;
            19) clear_old_logs ;;
            20)
                print_info "Exiting..."
                log_action "INFO" "========== Script Ended =========="
                exit 0
                ;;
            *)
                print_error "Invalid option. Choose 1-20."
                ;;
        esac
        
        echo
        read -rp "Press Enter to continue..."
    done
}

# Run the program
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
