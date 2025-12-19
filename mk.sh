#!/usr/bin/env bash
#
# MySQL Database Process Killer & Monitor
# Compatible with cPanel and DirectAdmin
# Version: 3.1 - Hardened & Safer Monitoring (English)
#

set -euo pipefail

# ---------- Colors ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'   # No Color
BOLD='\033[1m'

# ---------- Log path ----------
LOG_DIR="/var/log/mysql_killer"
LOG_FILE="${LOG_DIR}/mysql_killer.log"

# ---------- Logging (must be defined early) ----------
log_action() {
    local level="$1"; shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Write only if log file is available
    [[ "$LOG_FILE" != "/dev/null" ]] && echo "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE" 2>/dev/null || true
}

log_kill_action() {
    local action="$1"
    local target="$2"
    local count="$3"
    local details="${4:-}"
    log_action "KILL" "Action: ${action} | Target: ${target} | Count: ${count} | Details: ${details}"
}

# ---------- Helper output ----------
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

# ---------- Logging init ----------
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

# ---------- Safe formatting (column fallback) ----------
has_column() { command -v column >/dev/null 2>&1; }

safe_table() {
    # Read TSV from stdin. If `column` exists, align; otherwise print raw.
    if has_column; then
        column -t -s $'\t'
    else
        cat
    fi
}

# ---------- Input validation ----------
is_int() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

# Allows typical MySQL identifiers for DB/user in hosting environments.
# If you need hyphen/dot, expand the regex carefully.
is_mysql_ident() { [[ "${1:-}" =~ ^[A-Za-z0-9_\$]+$ ]]; }

# ---------- Cleanup ----------
cleanup() {
    [[ -n "${TMP_CNF:-}" && -f "$TMP_CNF" ]] && rm -f "$TMP_CNF"
}
trap cleanup EXIT

# ---------- Menu ----------
show_menu() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   MySQL Database Process Killer & Monitor v3.1             ║${NC}"
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

# ---------- Control panel detection ----------
detect_panel() {
    local panel="unknown"

    if [[ -f /usr/local/cpanel/cpanel ]] || [[ -d /var/cpanel ]] || [[ -f /etc/cpanel/cpanel.config ]]; then
        panel="cpanel"
    elif [[ -f /usr/local/directadmin/directadmin ]] || [[ -f /usr/local/directadmin/conf/mysql.conf ]]; then
        panel="directadmin"
    fi

    echo "$panel"
}

# ---------- MySQL setup: cPanel ----------
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

    if ! "${MYSQL_CMD[@]}" -e "SELECT 1;" >/dev/null 2>&1; then
        print_error "Failed to connect to MySQL with cPanel credentials"
        return 1
    fi

    return 0
}

# ---------- MySQL setup: DirectAdmin ----------
setup_da_mysql() {
    local da_conf="/usr/local/directadmin/conf/mysql.conf"

    if [[ ! -f "$da_conf" ]]; then
        print_error "DirectAdmin mysql.conf not found at $da_conf"
        return 1
    fi

    local da_user da_pass da_socket
    da_user=$(awk -F= '$1 ~ /^user$/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$da_conf" 2>/dev/null || true)
    da_pass=$(awk -F= '$1 ~ /^(passwd|password)$/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$da_conf" 2>/dev/null || true)
    da_socket=$(awk -F= '$1 ~ /^socket$/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$da_conf" 2>/dev/null || true)

    [[ -z "$da_user" ]] && da_user="da_admin"

    if [[ -z "$da_pass" ]]; then
        print_error "Could not read MySQL password from $da_conf"
        return 1
    fi

    # SECURITY: avoid exposing password in `ps` by using a temporary cnf
    TMP_CNF=$(mktemp /tmp/mysql_killer.XXXXXX.cnf)
    chmod 600 "$TMP_CNF" 2>/dev/null || true

    {
        echo "[client]"
        echo "user=$da_user"
        echo "password=$da_pass"
        if [[ -n "$da_socket" && -S "$da_socket" ]]; then
            echo "socket=$da_socket"
        fi
    } > "$TMP_CNF"

    MYSQL_CMD=(mysql --batch --skip-column-names --defaults-extra-file="$TMP_CNF")
    MYSQL_USER="$da_user"

    if ! "${MYSQL_CMD[@]}" -e "SELECT 1;" >/dev/null 2>&1; then
        print_error "Failed to connect to MySQL with DirectAdmin credentials"
        return 1
    fi

    return 0
}

# ---------- Monitoring: TOP databases ----------
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

    "${MYSQL_CMD[@]}" -e "$query" 2>/dev/null | while IFS=$'\t' read -r db count active sleep avg_t max_t users; do
        local color
        if [[ "${active:-0}" -gt 50 ]]; then
            color="${RED}${BOLD}"
        elif [[ "${active:-0}" -gt 20 ]]; then
            color="${YELLOW}"
        elif [[ "${active:-0}" -gt 5 ]]; then
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

# ---------- Monitoring: longest running queries ----------
show_databases_with_longest_queries() {
    print_header "Databases with Longest Running Queries"

    # FIX: avoid ONLY_FULL_GROUP_BY issues by selecting real rows and ordering by time
    local query="
    SELECT
        COALESCE(db, 'NULL') as database_name,
        time as longest_query,
        user,
        COALESCE(state, '') as state,
        LEFT(COALESCE(info, ''), 80) as query_sample
    FROM information_schema.processlist
    WHERE command='Query'
      AND user != '${MYSQL_USER}'
      AND time > 0
    ORDER BY time DESC
    LIMIT 20;
    "

    echo -e "${BOLD}Time(s) | Database | User | State | Query Sample${NC}"
    echo "─────────────────────────────────────────────────────────────────────────────"

    "${MYSQL_CMD[@]}" -e "$query" 2>/dev/null | while IFS=$'\t' read -r db time user state query_text; do
        local color
        if [[ "${time:-0}" -gt 300 ]]; then
            color="${RED}${BOLD}"
        elif [[ "${time:-0}" -gt 60 ]]; then
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

# ---------- Monitoring: DB connections ----------
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

    "${MYSQL_CMD[@]}" -e "$query" 2>/dev/null | while IFS=$'\t' read -r db conns users idle hosts; do
        local color
        if [[ "${conns:-0}" -gt 100 ]]; then
            color="${RED}${BOLD}"
        elif [[ "${conns:-0}" -gt 50 ]]; then
            color="${YELLOW}"
        else
            color="${GREEN}"
        fi

        printf "${color}%-25s${NC} | ${color}%-11s${NC} | %-5s | %-4s | %s\n" \
            "${db:0:25}" "$conns" "$users" "$idle" "${hosts:0:40}"
    done

    echo
}

# ---------- Monitoring: detailed stats per DB ----------
show_database_detailed_stats() {
    read -rp "Enter database name: " dbname
    [[ -z "$dbname" ]] && { print_error "Database name required."; return; }
    is_mysql_ident "$dbname" || { print_error "Invalid database name. Allowed: [A-Za-z0-9_\$]"; return; }

    print_header "Detailed Statistics for Database: $dbname"

    local total_queries sleeping active_queries max_time avg_time

    read -r total_queries sleeping active_queries max_time avg_time < <(
        "${MYSQL_CMD[@]}" -e "
        SELECT
            COALESCE(COUNT(*), 0),
            COALESCE(SUM(CASE WHEN command='Sleep' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN command='Query' THEN 1 ELSE 0 END), 0),
            COALESCE(MAX(time), 0),
            COALESCE(ROUND(AVG(time), 2), 0)
        FROM information_schema.processlist
        WHERE db='${dbname}';
        " 2>/dev/null | xargs
    )

    echo -e "${CYAN}Overview:${NC}"
    echo -e "  Total Processes: ${BOLD}${total_queries:-0}${NC}"
    echo -e "  Active Queries:  ${BOLD}${active_queries:-0}${NC}"
    echo -e "  Sleeping:        ${BOLD}${sleeping:-0}${NC}"
    echo -e "  Max Query Time:  ${BOLD}${max_time:-0}s${NC}"
    echo -e "  Avg Query Time:  ${BOLD}${avg_time:-0}s${NC}"
    echo

    echo -e "${CYAN}Users:${NC}"
    local user_data
    user_data=$("${MYSQL_CMD[@]}" -e "
    SELECT user, COUNT(*) as connections
    FROM information_schema.processlist
    WHERE db='${dbname}'
    GROUP BY user
    ORDER BY connections DESC;
    " 2>/dev/null || true)

    if [[ -n "$user_data" ]]; then
        printf "%s\n" "$user_data" | safe_table
    else
        echo "  No active users"
    fi
    echo

    echo -e "${CYAN}Query States:${NC}"
    local state_data
    state_data=$("${MYSQL_CMD[@]}" -e "
    SELECT COALESCE(state, 'NULL') as state, COUNT(*) as count
    FROM information_schema.processlist
    WHERE db='${dbname}' AND command='Query'
    GROUP BY state
    ORDER BY count DESC;
    " 2>/dev/null || true)

    if [[ -n "$state_data" ]]; then
        printf "%s\n" "$state_data" | safe_table
    else
        echo "  No active queries"
    fi
    echo

    echo -e "${CYAN}Top 5 Longest Queries:${NC}"
    local query_data
    query_data=$("${MYSQL_CMD[@]}" -e "
    SELECT id, user, time, LEFT(COALESCE(info,''), 100) as query
    FROM information_schema.processlist
    WHERE db='${dbname}' AND command='Query'
    ORDER BY time DESC
    LIMIT 5;
    " 2>/dev/null || true)

    if [[ -n "$query_data" ]]; then
        printf "%s\n" "$query_data" | safe_table
    else
        echo "  No active queries"
    fi
    echo
}

# ---------- Monitoring: TOP users ----------
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

    "${MYSQL_CMD[@]}" -e "$query" 2>/dev/null | while IFS=$'\t' read -r user total active sleep avg_t max_t dbs; do
        local color
        if [[ "${active:-0}" -gt 20 ]]; then
            color="${RED}${BOLD}"
        elif [[ "${active:-0}" -gt 10 ]]; then
            color="${YELLOW}"
        else
            color="${GREEN}"
        fi

        printf "${color}%-20s${NC} | %-5s | ${color}%-6s${NC} | %-5s | %-6s | %-6s | %s\n" \
            "${user:0:20}" "$total" "$active" "$sleep" "$avg_t" "$max_t" "$dbs"
    done

    echo
}

# ---------- Real-time monitor ----------
realtime_monitor() {
    local refresh_rate=3
    read -rp "Refresh interval in seconds [default: 3]: " input_rate
    [[ -n "${input_rate:-}" ]] && refresh_rate="$input_rate"

    is_int "$refresh_rate" || { print_error "Refresh interval must be a positive integer."; return; }
    (( refresh_rate >= 1 )) || { print_error "Refresh interval must be >= 1."; return; }

    print_info "Starting real-time monitor (refresh every ${refresh_rate}s). Press Ctrl+C to stop..."
    sleep 1

    while true; do
        clear
        print_header "Real-Time Process Monitor - $(date '+%Y-%m-%d %H:%M:%S')"

        local total_proc active_queries sleeping max_time
        read -r total_proc active_queries sleeping max_time < <(
            "${MYSQL_CMD[@]}" -e "
            SELECT
                COUNT(*),
                SUM(CASE WHEN command='Query' THEN 1 ELSE 0 END),
                SUM(CASE WHEN command='Sleep' THEN 1 ELSE 0 END),
                COALESCE(MAX(time), 0)
            FROM information_schema.processlist;
            " 2>/dev/null | xargs
        )

        echo -e "${BOLD}Server Summary:${NC} Total: $total_proc | Active: ${YELLOW}$active_queries${NC} | Sleep: $sleeping | Max Time: ${RED}${max_time}s${NC}"
        echo

        echo -e "${BOLD}TOP 10 Active Queries:${NC}"
        echo "─────────────────────────────────────────────────────────────────────────────"
        "${MYSQL_CMD[@]}" -e "
        SELECT id, user, COALESCE(db,'NULL') as db, time, LEFT(COALESCE(info,''), 60) as query
        FROM information_schema.processlist
        WHERE command='Query' AND user != '${MYSQL_USER}'
        ORDER BY time DESC
        LIMIT 10;
        " 2>/dev/null | safe_table

        sleep "$refresh_rate"
    done
}

# ---------- Server summary ----------
show_server_summary() {
    print_header "Server Load Summary"

    echo -e "${CYAN}${BOLD}MySQL Status:${NC}"

    # FIX: read each status variable deterministically (ORDER BY + xargs was unreliable)
    local uptime threads_conn threads_running queries
    uptime=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Uptime';" 2>/dev/null || echo 0)
    threads_conn=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Threads_connected';" 2>/dev/null || echo 0)
    threads_running=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Threads_running';" 2>/dev/null || echo 0)
    queries=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Queries';" 2>/dev/null || echo 0)

    local uptime_hours=0
    is_int "$uptime" && uptime_hours=$((uptime / 3600))

    echo -e "  Uptime: ${BOLD}${uptime_hours} hours${NC}"
    echo -e "  Threads Connected: ${BOLD}$threads_conn${NC}"
    echo -e "  Threads Running: ${BOLD}$threads_running${NC}"
    echo -e "  Total Queries: ${BOLD}$queries${NC}"
    echo

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
    " 2>/dev/null | safe_table
    echo

    echo -e "${CYAN}${BOLD}Active Databases:${NC}"
    local db_count
    db_count=$("${MYSQL_CMD[@]}" -e "
    SELECT COUNT(DISTINCT db)
    FROM information_schema.processlist
    WHERE db IS NOT NULL;
    " 2>/dev/null || echo 0)
    echo -e "  Total: ${BOLD}$db_count databases${NC}"
    echo

    if command -v uptime &> /dev/null; then
        echo -e "${CYAN}${BOLD}System Load:${NC}"
        uptime
        echo
    fi
}

# ---------- Processlist ----------
show_processlist() {
    local db="${1:-}"
    local query="SELECT id, user, host, COALESCE(db,'NULL') as db, command, time, COALESCE(state,'') as state, LEFT(COALESCE(info,''), 50) as query FROM information_schema.processlist"

    if [[ -n "$db" ]]; then
        is_mysql_ident "$db" || { print_error "Invalid database name. Allowed: [A-Za-z0-9_\$]"; return; }
        query="$query WHERE db='$db'"
    fi

    query="$query ORDER BY time DESC;"

    print_info "Active processes:"
    echo
    "${MYSQL_CMD[@]}" -e "$query" 2>/dev/null | safe_table
    echo
}

# ---------- Kill queries for a database ----------
kill_db_queries() {
    local db="$1"
    local command_filter="${2:-Query}"

    is_mysql_ident "$db" || { print_error "Invalid database name. Allowed: [A-Za-z0-9_\$]"; return; }

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

    read -rp "Found $count process(es). Kill them? (y/n): " confirm
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
            # FIX: ++ avoids set -e pitfalls of post-increment
            ((++killed))
            echo -ne "\r${GREEN}[✓]${NC} Killed: $killed/$count"
        else
            ((++failed))
        fi
    done <<< "$ids"

    echo
    print_success "Killed $killed process(es)."
    log_kill_action "Kill DB Queries" "$db" "$killed" "Command: $command_filter, Failed: $failed"
    [[ $failed -gt 0 ]] && print_warning "Failed to kill $failed process(es)."
}

# ---------- Kill long-running queries ----------
kill_long_queries() {
    local min_time="${1:-60}"

    is_int "$min_time" || { print_error "Minimum time must be an integer."; return; }

    print_info "Searching for queries running longer than $min_time seconds..."
    log_action "INFO" "Searching long queries (>${min_time}s)"

    local ids
    ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE command='Query' AND time > ${min_time} AND user != '${MYSQL_USER}';" 2>/dev/null || true)

    if [[ -z "${ids//[[:space:]]/}" ]]; then
        print_warning "No long-running queries found."
        return 0
    fi

    print_info "Long-running queries:"
    "${MYSQL_CMD[@]}" -e "
    SELECT id, user, COALESCE(db,'NULL') as db, time, LEFT(COALESCE(info,''), 100)
    FROM information_schema.processlist
    WHERE command='Query' AND time > ${min_time} AND user != '${MYSQL_USER}'
    ORDER BY time DESC;
    " 2>/dev/null | safe_table
    echo

    local count
    count=$(echo "$ids" | grep -c . || echo 0)

    read -rp "Kill $count process(es)? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_action "INFO" "Kill long queries aborted by user"
        return 0
    fi

    local killed=0
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1 && ((++killed))
    done <<< "$ids"

    print_success "Killed $killed process(es)."
    log_kill_action "Kill Long Queries" "Time>${min_time}s" "$killed" "Threshold: ${min_time}s"
}

# ---------- Kill sleeping connections ----------
kill_sleeping_connections() {
    local db="${1:-}"

    if [[ -n "$db" ]]; then
        is_mysql_ident "$db" || { print_error "Invalid database name. Allowed: [A-Za-z0-9_\$]"; return; }
    fi

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

    read -rp "Found $count sleeping connection(s). Kill them? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_action "INFO" "Kill sleeping connections aborted by user"
        return 0
    fi

    local killed=0
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1 && ((++killed))
    done <<< "$ids"

    print_success "Killed $killed sleeping connection(s)."
    log_kill_action "Kill Sleeping Connections" "${db:-all}" "$killed" "Command: Sleep"
}

# ---------- Kill all processes for a user ----------
kill_user_queries() {
    local username="$1"

    is_mysql_ident "$username" || { print_error "Invalid username. Allowed: [A-Za-z0-9_\$]"; return; }

    print_info "Searching for processes by user: $username"
    log_action "INFO" "Searching processes for user: $username"

    local ids
    ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE user='${username}' AND user != '${MYSQL_USER}';" 2>/dev/null || true)

    if [[ -z "${ids//[[:space:]]/}" ]]; then
        print_warning "No processes found for user '$username'."
        return 0
    fi

    "${MYSQL_CMD[@]}" -e "
    SELECT id, COALESCE(db,'NULL') as db, command, time, COALESCE(state,'') as state
    FROM information_schema.processlist
    WHERE user='${username}'
    ORDER BY time DESC;
    " 2>/dev/null | safe_table
    echo

    local count
    count=$(echo "$ids" | grep -c . || echo 0)

    read -rp "Kill $count process(es) for user '$username'? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_action "INFO" "Kill user processes aborted by user"
        return 0
    fi

    local killed=0
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1 && ((++killed))
    done <<< "$ids"

    print_success "Killed $killed process(es)."
    log_kill_action "Kill User Queries" "$username" "$killed" "Target user: $username"
}

# ---------- Kill a specific process ----------
kill_specific_process() {
    local pid="$1"

    is_int "$pid" || { print_error "Process ID must be numeric."; return 1; }

    local exists
    exists=$("${MYSQL_CMD[@]}" -e "SELECT COUNT(*) FROM information_schema.processlist WHERE id=${pid};" 2>/dev/null || echo "0")

    if [[ "$exists" == "0" ]]; then
        print_error "Process ID $pid not found."
        return 1
    fi

    print_info "Process details:"
    "${MYSQL_CMD[@]}" -e "SELECT * FROM information_schema.processlist WHERE id=${pid}\\G" 2>/dev/null || true
    echo

    read -rp "Kill this process? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_action "INFO" "Kill process $pid aborted by user"
        return 0
    fi

    if "${MYSQL_CMD[@]}" -e "KILL ${pid};" >/dev/null 2>&1; then
        print_success "Process $pid killed successfully."
        log_kill_action "Kill Specific Process" "PID:$pid" "1" "Process ID: $pid"
    else
        print_error "Failed to kill process $pid."
        log_action "ERROR" "Failed to kill process $pid"
        return 1
    fi
}

# ---------- Export report ----------
export_report() {
    local filename="mysql_report_$(date +%Y%m%d_%H%M%S).txt"

    print_info "Generating report..."
    log_action "INFO" "Exporting report to $filename"

    {
        echo "======================================================================"
        echo "MySQL Server Report"
        echo "Generated: $(date)"
        echo "======================================================================"
        echo

        echo "=== Server Summary ==="
        # Keep this robust inside report (no ORDER BY confusion)
        echo "Uptime:            $("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Uptime';" 2>/dev/null || echo 0)"
        echo "Threads_connected: $("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Threads_connected';" 2>/dev/null || echo 0)"
        echo "Threads_running:   $("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Threads_running';" 2>/dev/null || echo 0)"
        echo "Queries:           $("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Queries';" 2>/dev/null || echo 0)"
        echo

        echo "=== TOP Databases by Query Count ==="
        "${MYSQL_CMD[@]}" -e "
        SELECT COALESCE(db, 'NULL') as database_name, COUNT(*) as count
        FROM information_schema.processlist
        WHERE user != '${MYSQL_USER}'
        GROUP BY db
        ORDER BY count DESC
        LIMIT 20;" 2>/dev/null | safe_table
        echo

        echo "=== Active Processes ==="
        "${MYSQL_CMD[@]}" -e "
        SELECT id, user, COALESCE(db,'NULL') as db, command, time, COALESCE(state,'') as state, LEFT(COALESCE(info,''), 100)
        FROM information_schema.processlist
        ORDER BY time DESC;" 2>/dev/null | safe_table

    } > "$filename" 2>/dev/null || { print_error "Failed to write report file: $filename"; return 1; }

    print_success "Report saved to: $filename"
    log_action "INFO" "Report exported successfully: $filename"
}

# ---------- Slow Query Log status ----------
check_slow_query_log() {
    print_header "Slow Query Log Status"

    "${MYSQL_CMD[@]}" -e "
    SELECT VARIABLE_NAME, VARIABLE_VALUE
    FROM information_schema.GLOBAL_VARIABLES
    WHERE VARIABLE_NAME IN ('slow_query_log', 'slow_query_log_file', 'long_query_time');" 2>/dev/null | safe_table
    echo

    local log_enabled
    log_enabled=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_VARIABLES WHERE VARIABLE_NAME='slow_query_log';" 2>/dev/null || echo "")
    if [[ "$log_enabled" == "ON" ]]; then
        print_success "Slow query log is enabled"
        local log_file
        log_file=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_VARIABLES WHERE VARIABLE_NAME='slow_query_log_file';" 2>/dev/null || echo "")
        if [[ -n "$log_file" && -f "$log_file" ]]; then
            print_info "Log file: $log_file"
            print_info "Last 20 lines:"
            tail -n 20 "$log_file" 2>/dev/null || print_warning "Cannot read log file"
        fi
    else
        print_warning "Slow query log is disabled"
        print_info "To enable: SET GLOBAL slow_query_log = 'ON';"
    fi
}

# ---------- MySQL variables ----------
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
    ORDER BY VARIABLE_NAME;" 2>/dev/null | safe_table
    echo
}

# ---------- View logs ----------
view_logs() {
    print_header "Operation Logs"

    if [[ ! -f "$LOG_FILE" ]] || [[ "$LOG_FILE" == "/dev/null" ]]; then
        print_warning "No log file found or logging is disabled."
        print_info "Log file location: $LOG_FILE"
        return
    fi

    local log_size
    log_size=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)

    print_info "Log file: $LOG_FILE"
    print_info "Total lines: $log_size"
    echo

    if [[ $log_size -eq 0 ]]; then
        print_warning "Log file is empty."
        return
    fi

    read -rp "Show last N lines [default: 50]: " lines
    lines="${lines:-50}"
    is_int "$lines" || lines=50

    echo -e "${CYAN}Last ${lines} log entries:${NC}"
    echo "─────────────────────────────────────────────────────────────────────────────"
    tail -n "$lines" "$LOG_FILE" | while IFS= read -r line; do
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

    echo -e "${CYAN}Log Statistics:${NC}"
    local total_kills warnings errors
    total_kills=$(grep -c "\[KILL\]" "$LOG_FILE" 2>/dev/null || echo 0)
    warnings=$(grep -c "\[WARNING\]" "$LOG_FILE" 2>/dev/null || echo 0)
    errors=$(grep -c "\[ERROR\]" "$LOG_FILE" 2>/dev/null || echo 0)

    echo "  Total Kill Operations: ${BOLD}$total_kills${NC}"
    echo "  Warnings: ${YELLOW}$warnings${NC}"
    echo "  Errors: ${RED}$errors${NC}"
    echo
}

# ---------- Clear logs ----------
clear_old_logs() {
    if [[ ! -f "$LOG_FILE" ]] || [[ "$LOG_FILE" == "/dev/null" ]]; then
        print_warning "No log file found."
        return
    fi

    local log_size
    log_size=$(du -h "$LOG_FILE" 2>/dev/null | cut -f1 || echo "unknown")

    print_warning "Current log file size: $log_size"
    read -rp "This will clear all logs. Continue? (y/n): " confirm

    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        : > "$LOG_FILE"
        print_success "Logs cleared successfully."
        log_action "INFO" "Logs cleared by user"
    else
        print_info "Operation cancelled."
    fi
}

# ---------- Main ----------
main() {
    init_logging || true

    if [[ "$LOG_FILE" != "/dev/null" ]]; then
        print_success "Logging enabled: $LOG_FILE"
    fi

    log_action "INFO" "========== Script Started =========="

    PANEL=$(detect_panel)

    if [[ "$PANEL" == "unknown" ]]; then
        print_error "Could not detect cPanel or DirectAdmin."
        print_info "Please ensure the server has cPanel or DirectAdmin installed."
        log_action "ERROR" "Panel detection failed"
        exit 1
    fi

    print_success "Detected control panel: $PANEL"
    log_action "INFO" "Panel detected: $PANEL"

    if [[ "$PANEL" == "cpanel" ]]; then
        setup_cpanel_mysql || exit 2
    elif [[ "$PANEL" == "directadmin" ]]; then
        setup_da_mysql || exit 2
    fi

    print_success "MySQL connection configured (User: $MYSQL_USER)"
    log_action "INFO" "MySQL connection established as: $MYSQL_USER"
    echo
    sleep 1

    while true; do
        show_menu
        read -rp "Select an option [1-20]: " choice
        echo

        case $choice in
            1)  show_top_databases_by_queries ;;
            2)  show_databases_with_longest_queries ;;
            3)  show_databases_by_connections ;;
            4)  show_database_detailed_stats ;;
            5)  show_top_users ;;
            6)  realtime_monitor ;;
            7)  show_server_summary ;;
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
            13) show_processlist ;;
            14)
                read -rp "Enter database name (or press Enter for all): " dbname
                kill_sleeping_connections "$dbname"
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
                print_error "Invalid option. Please select 1-20."
                ;;
        esac

        echo
        read -rp "Press Enter to continue..."
    done
}

main
