#!/usr/bin/env bash
#
# MySQL Database Process Killer & Monitor
# Compatible with cPanel and DirectAdmin
# Version: 3.1 - Bugfix + Hardening + English
#

set -euo pipefail

# ---------- Colors ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

# ---------- Logging ----------
LOG_DIR="/var/log/mysql_killer"
LOG_FILE="${LOG_DIR}/mysql_killer.log"

log_action() {
    local level="$1"; shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    [[ "$LOG_FILE" != "/dev/null" ]] && echo "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE" 2>/dev/null || true
}

log_kill_action() {
    local action="$1"
    local target="$2"
    local count="$3"
    local details="${4:-}"
    log_action "KILL" "Action: ${action} | Target: ${target} | Count: ${count} | Details: ${details}"
}

print_error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; log_action "INFO" "$1"; }
print_info()    { echo -e "${BLUE}[*]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; log_action "WARNING" "$1"; }

init_logging() {
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR" 2>/dev/null || {
            LOG_DIR="/root/mysql_killer_logs"
            LOG_FILE="${LOG_DIR}/mysql_killer.log"
            mkdir -p "$LOG_DIR" 2>/dev/null || { LOG_FILE="/dev/null"; return 1; }
        }
    fi
    touch "$LOG_FILE" 2>/dev/null || { LOG_FILE="/dev/null"; return 1; }
    chmod 600 "$LOG_FILE" 2>/dev/null || true
    return 0
}

print_header() {
    echo -e "${CYAN}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║          $1${NC}"
    echo -e "${CYAN}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# ---------- Helpers ----------
is_tty() { [[ -t 1 ]]; }

safe_clear() {
    if is_tty && [[ -n "${TERM:-}" ]]; then
        command -v clear >/dev/null 2>&1 && clear || true
    fi
}

need_cmd() {
    local c="$1"
    command -v "$c" >/dev/null 2>&1
}

# Basic SQL literal escaping for single quotes
sql_escape() {
    # Replace ' with '' and remove control chars
    local s="$1"
    s=${s//$'\n'/ }
    s=${s//$'\r'/ }
    s=${s//$'\t'/ }
    s=${s//\'/\'\'}
    printf '%s' "$s"
}

# Safer integer check
is_uint() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

cleanup() {
    [[ -n "${TMP_CNF:-}" && -f "$TMP_CNF" ]] && rm -f "$TMP_CNF" || true
}
trap cleanup EXIT

detect_panel() {
    local panel="unknown"
    if [[ -f /usr/local/cpanel/cpanel ]] || [[ -d /var/cpanel ]] || [[ -f /etc/cpanel/cpanel.config ]]; then
        panel="cpanel"
    elif [[ -f /usr/local/directadmin/directadmin ]] || [[ -f /usr/local/directadmin/conf/mysql.conf ]]; then
        panel="directadmin"
    fi
    echo "$panel"
}

# ---------- MySQL setup (Requested syntax: --defaults-file=...) ----------
setup_cpanel_mysql() {
    # Pick credentials file
    if [[ -f /root/.my.cnf ]]; then
        MYSQL_CNF="/root/.my.cnf"
    elif [[ -f /root/my.cnf ]]; then
        print_warning "/root/.my.cnf not found. Using /root/my.cnf..."
        MYSQL_CNF="/root/my.cnf"
    else
        print_error "Neither /root/.my.cnf nor /root/my.cnf found."
        return 1
    fi

    # Tight perms (best practice; avoids warnings/risk)
    chmod 600 "$MYSQL_CNF" 2>/dev/null || true

    MYSQL_USER="root"

    # IMPORTANT: defaults-file must be first after mysql
    MYSQL_CMD=(mysql --defaults-file="$MYSQL_CNF" --batch --skip-column-names)

    # Test (fallback to defaults-extra-file, also placed first after mysql)
    if ! "${MYSQL_CMD[@]}" -e "SELECT 1;" >/dev/null 2>&1; then
        MYSQL_CMD=(mysql --defaults-extra-file="$MYSQL_CNF" --batch --skip-column-names)
        if ! "${MYSQL_CMD[@]}" -e "SELECT 1;" >/dev/null 2>&1; then
            print_error "Failed to connect to MySQL with cPanel credentials file: $MYSQL_CNF"
            return 1
        fi
    fi

    return 0
}

setup_da_mysql() {
    MYSQL_CNF="/usr/local/directadmin/conf/my.cnf"
    if [[ ! -f "$MYSQL_CNF" ]]; then
        print_error "DirectAdmin MySQL credentials file not found: $MYSQL_CNF"
        return 1
    fi

    # Tight perms (best practice; avoids warnings/risk)
    chmod 600 "$MYSQL_CNF" 2>/dev/null || true

    # Most DA setups use root/admin creds in this file (if [client] exists)
    MYSQL_USER="root"

    # IMPORTANT: defaults-file must be first after mysql
    MYSQL_CMD=(mysql --defaults-file="$MYSQL_CNF" --batch --skip-column-names)

    # Test (fallback to defaults-extra-file, also placed first after mysql)
    if ! "${MYSQL_CMD[@]}" -e "SELECT 1;" >/dev/null 2>&1; then
        MYSQL_CMD=(mysql --defaults-extra-file="$MYSQL_CNF" --batch --skip-column-names)
        if ! "${MYSQL_CMD[@]}" -e "SELECT 1;" >/dev/null 2>&1; then
            print_error "Failed to connect to MySQL with DirectAdmin credentials file: $MYSQL_CNF"
            return 1
        fi
    fi

    return 0
}

# ---------- UI ----------
show_menu() {
    safe_clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   MySQL Database Process Killer & Monitor v3.1            ║${NC}"
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

# ---------- Adaptive display helpers (DISPLAY-ONLY) ----------
term_cols() {
    local c=120
    if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
        c=$(tput cols 2>/dev/null || echo 120)
    fi
    [[ -z "${c//[[:space:]]/}" ]] && c=120
    (( c < 60 )) && c=60
    echo "$c"
}

truncate_ellipsis() {
    # Args: text, width
    local s="$1"
    local w="${2:-0}"
    (( w <= 0 )) && { printf ""; return; }
    if (( ${#s} <= w )); then
        printf "%s" "$s"
        return
    fi
    if (( w == 1 )); then
        printf "…"
        return
    fi
    printf "%s…" "${s:0:w-1}"
}

pad_right() {
    # Args: text, width  (no ANSI inside text)
    local s="$1"
    local w="${2:-0}"
    printf "%-*s" "$w" "$s"
}

# Print table (TAB-separated) with adaptive width and safe truncation
print_table() {
    # If not interactive, keep raw (important for exports)
    if [[ ! -t 1 ]]; then
        cat
        return 0
    fi

    local term_w
    term_w=$(term_cols)

    # Expect TAB-separated input
    awk -v W="$term_w" -v FS='\t' '
        function len(s){ return length(s) }

        function trunc(s, w,    l) {
            l = len(s)
            if (w <= 0) return ""
            if (l <= w) return s
            if (w == 1) return "…"
            return substr(s, 1, w-1) "…"
        }

        {
            rowc++
            for (i=1; i<=NF; i++) {
                cell[rowc, i] = $i
                if (len($i) > maxw[i]) maxw[i] = len($i)
                if (i > colc) colc = i
            }
            nfc[rowc] = NF
        }

        END {
            if (rowc == 0) exit

            sep = " | "
            seplen = len(sep)

            for (i=1; i<=colc; i++) {
                w[i] = maxw[i]
                if (w[i] > 80) w[i] = 80
                if (w[i] < 4)  w[i] = 4
            }

            total = 0
            for (i=1; i<=colc; i++) total += w[i]
            total += (colc-1) * seplen

            minw = (W < 80 ? 4 : 6)

            while (total > W) {
                wi = 1
                for (i=2; i<=colc; i++) if (w[i] > w[wi]) wi = i
                if (w[wi] <= minw) break
                w[wi]--
                total--
            }

            for (r=1; r<=rowc; r++) {
                for (i=1; i<=colc; i++) {
                    s = cell[r,i]
                    if (i > nfc[r]) s = ""
                    s = trunc(s, w[i])
                    printf "%-*s", w[i], s
                    if (i < colc) printf "%s", sep
                }
                printf "\n"
            }
        }
    '
}

# ---------- Monitoring ----------
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

    local cols db_w=25 total_w=5 active_w=6 sleep_w=5 avg_w=6 max_w=6
    cols=$(term_cols)

    # separators: 7 columns -> 6 separators * 3 chars
    local fixed=$(( db_w + total_w + active_w + sleep_w + avg_w + max_w ))
    local seps=$(( 6 * 3 ))
    local users_w=$(( cols - fixed - seps ))
    (( users_w < 10 )) && users_w=10

    "${MYSQL_CMD[@]}" -e "$query" 2>/dev/null | while IFS=$'\t' read -r db count active sleep avg_t max_t users; do
        local color
        if [[ ${active:-0} -gt 50 ]]; then
            color="${RED}${BOLD}"
        elif [[ ${active:-0} -gt 20 ]]; then
            color="${YELLOW}"
        elif [[ ${active:-0} -gt 5 ]]; then
            color="${CYAN}"
        else
            color="${GREEN}"
        fi

        db=$(truncate_ellipsis "${db:-NULL}" "$db_w")
        users=$(truncate_ellipsis "${users:-}" "$users_w")

        printf "%s%s${NC} | %s | %s%s${NC} | %s | %s | %s | %s\n" \
            "$color" "$(pad_right "$db" "$db_w")" \
            "$(pad_right "${count:-0}" "$total_w")" \
            "$color" "$(pad_right "${active:-0}" "$active_w")" \
            "$(pad_right "${sleep:-0}" "$sleep_w")" \
            "$(pad_right "${avg_t:-0}" "$avg_w")" \
            "$(pad_right "${max_t:-0}" "$max_w")" \
            "$users"
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

    local cols time_w=7 db_w=20 user_w=15 state_w=20
    cols=$(term_cols)

    # 5 columns -> 4 separators
    local fixed=$(( time_w + db_w + user_w + state_w ))
    local seps=$(( 4 * 3 ))
    local qs_w=$(( cols - fixed - seps ))
    (( qs_w < 15 )) && qs_w=15

    # FIX: correct mapping: db, time, count, user, state, query_text
    "${MYSQL_CMD[@]}" -e "$query" 2>/dev/null | while IFS=$'\t' read -r db time count user state query_text; do
        local color
        if [[ ${time:-0} -gt 300 ]]; then
            color="${RED}${BOLD}"
        elif [[ ${time:-0} -gt 60 ]]; then
            color="${YELLOW}"
        else
            color="${CYAN}"
        fi

        local t dbv uv sv qv
        t=$(truncate_ellipsis "${time:-0}" "$time_w")
        dbv=$(truncate_ellipsis "${db:-NULL}" "$db_w")
        uv=$(truncate_ellipsis "${user:-}" "$user_w")
        sv=$(truncate_ellipsis "${state:-}" "$state_w")
        qv=$(truncate_ellipsis "${query_text:-}" "$qs_w")

        printf "%s%s${NC} | %s | %s | %s | %s\n" \
            "$color" "$(pad_right "$t" "$time_w")" \
            "$(pad_right "$dbv" "$db_w")" \
            "$(pad_right "$uv" "$user_w")" \
            "$(pad_right "$sv" "$state_w")" \
            "$qv"
    done

    echo
    print_info "Queries running for: ${RED}>300s = Critical${NC} | ${YELLOW}>60s = Warning${NC}"
}

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

    local cols db_w=25 conns_w=11 users_w=5 idle_w=4
    cols=$(term_cols)

    # 5 columns -> 4 separators
    local fixed=$(( db_w + conns_w + users_w + idle_w ))
    local seps=$(( 4 * 3 ))
    local hosts_w=$(( cols - fixed - seps ))
    (( hosts_w < 15 )) && hosts_w=15

    "${MYSQL_CMD[@]}" -e "$query" 2>/dev/null | while IFS=$'\t' read -r db conns users idle hosts; do
        local color
        if [[ ${conns:-0} -gt 100 ]]; then
            color="${RED}${BOLD}"
        elif [[ ${conns:-0} -gt 50 ]]; then
            color="${YELLOW}"
        else
            color="${GREEN}"
        fi

        local dbv hv
        dbv=$(truncate_ellipsis "${db:-NULL}" "$db_w")
        hv=$(truncate_ellipsis "${hosts:-}" "$hosts_w")

        printf "%s%s${NC} | %s%s${NC} | %s | %s | %s\n" \
            "$color" "$(pad_right "$dbv" "$db_w")" \
            "$color" "$(pad_right "${conns:-0}" "$conns_w")" \
            "$(pad_right "${users:-0}" "$users_w")" \
            "$(pad_right "${idle:-0}" "$idle_w")" \
            "$hv"
    done

    echo
}

show_database_detailed_stats() {
    read -rp "Enter database name: " dbname
    [[ -z "$dbname" ]] && { print_error "Database name required."; return 0; }

    local db_esc
    db_esc=$(sql_escape "$dbname")

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
        WHERE db='${db_esc}';
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
    WHERE db='${db_esc}'
    GROUP BY user;
    " 2>/dev/null || true)

    if [[ -n "${user_data//[[:space:]]/}" ]]; then
        echo "$user_data" | print_table
    else
        echo "  No active users"
    fi
    echo

    echo -e "${CYAN}Query States:${NC}"
    local state_data
    state_data=$("${MYSQL_CMD[@]}" -e "
    SELECT COALESCE(state, 'NULL') as state, COUNT(*) as count
    FROM information_schema.processlist
    WHERE db='${db_esc}' AND command='Query'
    GROUP BY state
    ORDER BY count DESC;
    " 2>/dev/null || true)

    if [[ -n "${state_data//[[:space:]]/}" ]]; then
        echo "$state_data" | print_table
    else
        echo "  No active queries"
    fi
    echo

    echo -e "${CYAN}Top 5 Longest Queries:${NC}"
    local query_data
    query_data=$("${MYSQL_CMD[@]}" -e "
    SELECT id, user, time, LEFT(info, 100) as query
    FROM information_schema.processlist
    WHERE db='${db_esc}' AND command='Query'
    ORDER BY time DESC
    LIMIT 5;
    " 2>/dev/null || true)

    if [[ -n "${query_data//[[:space:]]/}" ]]; then
        echo "$query_data" | print_table
    else
        echo "  No active queries"
    fi
    echo
}

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

    local cols user_w=20 total_w=5 active_w=6 sleep_w=5 avg_w=6 max_w=6
    cols=$(term_cols)

    # 7 columns -> 6 separators
    local fixed=$(( user_w + total_w + active_w + sleep_w + avg_w + max_w ))
    local seps=$(( 6 * 3 ))
    local dbs_w=$(( cols - fixed - seps ))
    (( dbs_w < 3 )) && dbs_w=3
    (( dbs_w > 10 )) && dbs_w=10  # DB count is numeric; keep it sane

    "${MYSQL_CMD[@]}" -e "$query" 2>/dev/null | while IFS=$'\t' read -r user total active sleep avg_t max_t dbs; do
        local color
        if [[ ${active:-0} -gt 20 ]]; then
            color="${RED}${BOLD}"
        elif [[ ${active:-0} -gt 10 ]]; then
            color="${YELLOW}"
        else
            color="${GREEN}"
        fi

        local uv
        uv=$(truncate_ellipsis "${user:-}" "$user_w")

        printf "%s%s${NC} | %s | %s%s${NC} | %s | %s | %s | %s\n" \
            "$color" "$(pad_right "$uv" "$user_w")" \
            "$(pad_right "${total:-0}" "$total_w")" \
            "$color" "$(pad_right "${active:-0}" "$active_w")" \
            "$(pad_right "${sleep:-0}" "$sleep_w")" \
            "$(pad_right "${avg_t:-0}" "$avg_w")" \
            "$(pad_right "${max_t:-0}" "$max_w")" \
            "$(pad_right "${dbs:-0}" "$dbs_w")"
    done

    echo
}

realtime_monitor() {
    local refresh_rate=3
    read -rp "Refresh interval in seconds [default: 3]: " input_rate
    if [[ -n "$input_rate" ]]; then
        if is_uint "$input_rate" && [[ "$input_rate" -ge 1 && "$input_rate" -le 60 ]]; then
            refresh_rate="$input_rate"
        else
            print_warning "Invalid refresh rate, using default (3)."
        fi
    fi

    print_info "Starting real-time monitor (every ${refresh_rate}s). Press Ctrl+C to stop..."
    sleep 1

    trap 'echo; print_info "Real-time monitor stopped."; log_action "INFO" "Real-time monitor stopped."; return 0' INT

    while true; do
        safe_clear
        print_header "Real-Time Process Monitor - $(date '+%Y-%m-%d %H:%M:%S')"

        local total_proc active_queries sleeping max_time
        read -r total_proc active_queries sleeping max_time < <(
            "${MYSQL_CMD[@]}" -e "
            SELECT
                COUNT(*),
                SUM(CASE WHEN command='Query' THEN 1 ELSE 0 END),
                SUM(CASE WHEN command='Sleep' THEN 1 ELSE 0 END),
                MAX(time)
            FROM information_schema.processlist;
            " 2>/dev/null | xargs
        )

        echo -e "${BOLD}Server Summary:${NC} Total: ${total_proc:-0} | Active: ${YELLOW}${active_queries:-0}${NC} | Sleep: ${sleeping:-0} | Max Time: ${RED}${max_time:-0}s${NC}"
        echo

        echo -e "${BOLD}TOP 10 Active Queries:${NC}"
        echo "─────────────────────────────────────────────────────────────────────────────"
        "${MYSQL_CMD[@]}" -e "
        SELECT id, user, db, time, LEFT(info, 60) as query
        FROM information_schema.processlist
        WHERE command='Query' AND user != '${MYSQL_USER}'
        ORDER BY time DESC
        LIMIT 10;
        " 2>/dev/null | print_table

        sleep "$refresh_rate"
    done
}

show_server_summary() {
    print_header "Server Load Summary"

    echo -e "${CYAN}${BOLD}MySQL Status:${NC}"

    # FIX: stable mapping (no ORDER BY tricks)
    local uptime threads_conn threads_running queries
    uptime=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Uptime';" 2>/dev/null || echo 0)
    threads_conn=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Threads_connected';" 2>/dev/null || echo 0)
    threads_running=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Threads_running';" 2>/dev/null || echo 0)
    queries=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Queries';" 2>/dev/null || echo 0)

    [[ -z "${uptime//[[:space:]]/}" ]] && uptime=0
    if ! is_uint "$uptime"; then uptime=0; fi

    local uptime_hours=$(( uptime / 3600 ))
    echo -e "  Uptime:           ${BOLD}${uptime_hours} hours${NC}"
    echo -e "  Threads Connected:${BOLD}${threads_conn:-0}${NC}"
    echo -e "  Threads Running:  ${BOLD}${threads_running:-0}${NC}"
    echo -e "  Total Queries:    ${BOLD}${queries:-0}${NC}"
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
    " 2>/dev/null | print_table
    echo

    echo -e "${CYAN}${BOLD}Active Databases:${NC}"
    local db_count
    db_count=$("${MYSQL_CMD[@]}" -e "
    SELECT COUNT(DISTINCT db)
    FROM information_schema.processlist
    WHERE db IS NOT NULL;
    " 2>/dev/null || echo 0)
    echo -e "  Total: ${BOLD}${db_count:-0} databases${NC}"
    echo

    if need_cmd uptime; then
        echo -e "${CYAN}${BOLD}System Load:${NC}"
        uptime || true
        echo
    fi
}

show_processlist() {
    local db="${1:-}"
    local query="SELECT id, user, host, db, command, time, state, LEFT(info, 50) as query FROM information_schema.processlist"
    if [[ -n "$db" ]]; then
        local db_esc
        db_esc=$(sql_escape "$db")
        query="$query WHERE db='$db_esc'"
    fi
    query="$query ORDER BY time DESC;"

    print_info "Active processes:"
    echo
    "${MYSQL_CMD[@]}" -e "$query" 2>/dev/null | print_table
    echo
}

# ---------- Kill ops (hardened) ----------
kill_ids_list() {
    # Args: newline-separated IDs, label, details
    local ids="$1"
    local label="$2"
    local details="${3:-}"

    local count
    count=$(echo "$ids" | grep -c . 2>/dev/null || echo 0)

    local confirm
    print_warning "Found $count process(es). Kill them? (y/n): "
    read -r confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        print_info "Aborted."
        log_action "INFO" "Kill aborted: $label"
        return 0
    fi

    local killed=0 failed=0
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        if "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1; then
            killed=$((killed+1))
            echo -ne "\r${GREEN}[✓]${NC} Killed: $killed/$count"
        else
            failed=$((failed+1))
        fi
    done <<< "$ids"
    echo

    print_success "Killed $killed process(es)."
    log_kill_action "$label" "IDs" "$killed" "$details | Failed: $failed"
    [[ $failed -gt 0 ]] && print_warning "Failed to kill $failed process(es)."
}

kill_db_queries() {
    local db="$1"
    local command_filter="${2:-Query}"

    local db_esc
    db_esc=$(sql_escape "$db")

    print_info "Searching for processes in database: $db (Command: $command_filter)"
    log_action "INFO" "Searching processes in DB: $db, Command: $command_filter"

    local ids
    ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE db='${db_esc}' AND command='${command_filter}' AND user != '${MYSQL_USER}';" 2>/dev/null || true)

    if [[ -z "${ids//[[:space:]]/}" ]]; then
        print_warning "No processes found for database '$db' with command '$command_filter'."
        return 0
    fi

    kill_ids_list "$ids" "Kill DB Queries" "DB: $db | Command: $command_filter"
}

kill_long_queries() {
    local min_time="${1:-60}"
    if ! is_uint "$min_time"; then
        print_error "Invalid time threshold."
        return 0
    fi

    print_info "Searching for queries running longer than $min_time seconds..."
    log_action "INFO" "Searching long queries (>${min_time}s)"

    local ids
    ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE command='Query' AND time > ${min_time} AND user != '${MYSQL_USER}';" 2>/dev/null || true)

    if [[ -z "${ids//[[:space:]]/}" ]]; then
        print_warning "No long-running queries found."
        return 0
    fi

    print_info "Long-running queries:"
    "${MYSQL_CMD[@]}" -e "SELECT id, user, db, time, LEFT(info, 100) FROM information_schema.processlist WHERE command='Query' AND time > ${min_time} AND user != '${MYSQL_USER}';" 2>/dev/null | print_table
    echo

    kill_ids_list "$ids" "Kill Long Queries" "Threshold: ${min_time}s"
}

kill_sleeping_connections() {
    local db="${1:-}"
    local where_clause="command='Sleep'"
    if [[ -n "$db" ]]; then
        local db_esc
        db_esc=$(sql_escape "$db")
        where_clause="$where_clause AND db='$db_esc'"
    fi
    where_clause="$where_clause AND user != '${MYSQL_USER}'"

    print_info "Searching for sleeping connections..."
    log_action "INFO" "Searching sleeping connections, DB: ${db:-all}"

    local ids
    ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE ${where_clause};" 2>/dev/null || true)

    if [[ -z "${ids//[[:space:]]/}" ]]; then
        print_warning "No sleeping connections found."
        return 0
    fi

    kill_ids_list "$ids" "Kill Sleeping Connections" "DB: ${db:-all}"
}

kill_user_queries() {
    local username="$1"
    local user_esc
    user_esc=$(sql_escape "$username")

    print_info "Searching for processes by user: $username"
    log_action "INFO" "Searching processes for user: $username"

    local ids
    ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE user='${user_esc}' AND user != '${MYSQL_USER}';" 2>/dev/null || true)

    if [[ -z "${ids//[[:space:]]/}" ]]; then
        print_warning "No processes found for user '$username'."
        return 0
    fi

    "${MYSQL_CMD[@]}" -e "SELECT id, db, command, time, state FROM information_schema.processlist WHERE user='${user_esc}';" 2>/dev/null | print_table
    echo

    kill_ids_list "$ids" "Kill User Queries" "User: $username"
}

kill_specific_process() {
    local pid="$1"
    if ! is_uint "$pid"; then
        print_error "Process ID must be a number."
        return 0
    fi

    local exists
    exists=$("${MYSQL_CMD[@]}" -e "SELECT COUNT(*) FROM information_schema.processlist WHERE id=${pid};" 2>/dev/null || echo "0")
    [[ -z "${exists//[[:space:]]/}" ]] && exists=0

    if [[ "$exists" == "0" ]]; then
        print_error "Process ID $pid not found."
        return 0
    fi

    print_info "Process details:"
    "${MYSQL_CMD[@]}" -e "SELECT * FROM information_schema.processlist WHERE id=${pid}\\G" 2>/dev/null || true
    echo

    local confirm
    print_warning "Kill this process? (y/n): "
    read -r confirm
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
        return 0
    fi
}

# ---------- Advanced ----------
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
        "${MYSQL_CMD[@]}" -e "
        SELECT VARIABLE_NAME, VARIABLE_VALUE
        FROM information_schema.GLOBAL_STATUS
        WHERE VARIABLE_NAME IN ('Uptime', 'Threads_connected', 'Threads_running', 'Questions', 'Queries');
        " 2>/dev/null | print_table
        echo

        echo "=== TOP Databases by Query Count ==="
        "${MYSQL_CMD[@]}" -e "
        SELECT COALESCE(db, 'NULL') as database_name, COUNT(*) as count
        FROM information_schema.processlist
        WHERE user != '${MYSQL_USER}'
        GROUP BY db ORDER BY count DESC LIMIT 20;
        " 2>/dev/null | print_table
        echo

        echo "=== Active Processes ==="
        "${MYSQL_CMD[@]}" -e "
        SELECT id, user, db, command, time, state, LEFT(info, 100)
        FROM information_schema.processlist
        ORDER BY time DESC;
        " 2>/dev/null | print_table

    } > "$filename"

    print_success "Report saved to: $filename"
    log_action "INFO" "Report exported successfully: $filename"
}

check_slow_query_log() {
    print_header "Slow Query Log Status"

    "${MYSQL_CMD[@]}" -e "
    SELECT VARIABLE_NAME, VARIABLE_VALUE
    FROM information_schema.GLOBAL_VARIABLES
    WHERE VARIABLE_NAME IN ('slow_query_log', 'slow_query_log_file', 'long_query_time');
    " 2>/dev/null | print_table
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
        else
            print_warning "Slow log file path is not accessible."
        fi
    else
        print_warning "Slow query log is disabled"
        print_info "To enable: SET GLOBAL slow_query_log = 'ON';"
    fi
}

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
    ORDER BY VARIABLE_NAME;
    " 2>/dev/null | print_table
    echo
}

view_logs() {
    print_header "Operation Logs"

    if [[ ! -f "$LOG_FILE" ]] || [[ "$LOG_FILE" == "/dev/null" ]]; then
        print_warning "No log file found or logging is disabled."
        print_info "Log file location: $LOG_FILE"
        return 0
    fi

    local log_size
    log_size=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)

    print_info "Log file: $LOG_FILE"
    print_info "Total lines: $log_size"
    echo

    if [[ $log_size -eq 0 ]]; then
        print_warning "Log file is empty."
        return 0
    fi

    read -rp "Show last N lines [default: 50]: " lines
    lines="${lines:-50}"
    if ! is_uint "$lines"; then lines=50; fi

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
    echo "  Warnings:             ${YELLOW}$warnings${NC}"
    echo "  Errors:               ${RED}$errors${NC}"
    echo
}

clear_old_logs() {
    if [[ ! -f "$LOG_FILE" ]] || [[ "$LOG_FILE" == "/dev/null" ]]; then
        print_warning "No log file found."
        return 0
    fi

    local log_size
    log_size=$(du -h "$LOG_FILE" 2>/dev/null | cut -f1 || echo "unknown")

    print_warning "Current log file size: $log_size"
    print_warning "This will clear all logs. Continue? (y/n): "
    read -r confirm

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

    local PANEL
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
            *)  print_error "Invalid option. Please select 1-20." ;;
        esac

        echo
        read -rp "Press Enter to continue..."
    done
}

main
