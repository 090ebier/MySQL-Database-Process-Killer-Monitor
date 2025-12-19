#!/usr/bin/env bash
#
# MySQL Process Killer & Monitor
# Compatible with cPanel and DirectAdmin
# Version: 3.1 - Hardened & Safer Monitoring
#

set -euo pipefail

# -------- Colors --------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

# -------- Logging --------
LOG_DIR="/var/log/mysql_killer"
LOG_FILE="${LOG_DIR}/mysql_killer.log"

log_action() {
  local level="$1"; shift
  local message="$*"
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  [[ "$LOG_FILE" != "/dev/null" ]] && echo "[${ts}] [${level}] ${message}" >> "$LOG_FILE" 2>/dev/null || true
}

log_kill_action() {
  local action="$1" target="$2" count="$3" details="${4:-}"
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

has_column() { command -v column >/dev/null 2>&1; }

safe_table() {
  # Reads TSV from stdin. If `column` exists, align; otherwise print raw.
  if has_column; then column -t -s $'\t'; else cat; fi
}

# -------- Cleanup --------
cleanup() {
  [[ -n "${TMP_CNF:-}" && -f "$TMP_CNF" ]] && rm -f "$TMP_CNF"
}
trap cleanup EXIT

# -------- Input validation (whitelist) --------
is_int() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }
is_mysql_ident() {
  # Allows typical DB/user identifiers: letters, numbers, underscore, dollar
  [[ "${1:-}" =~ ^[A-Za-z0-9_\$]+$ ]]
}

# -------- Panel detection --------
detect_panel() {
  if [[ -f /usr/local/cpanel/cpanel ]] || [[ -d /var/cpanel ]] || [[ -f /etc/cpanel/cpanel.config ]]; then
    echo "cpanel"
  elif [[ -f /usr/local/directadmin/directadmin ]] || [[ -f /usr/local/directadmin/conf/mysql.conf ]]; then
    echo "directadmin"
  else
    echo "unknown"
  fi
}

# -------- MySQL setup --------
setup_cpanel_mysql() {
  local cnf=""
  if [[ -f /root/.my.cnf ]]; then
    cnf="/root/.my.cnf"
  elif [[ -f /root/my.cnf ]]; then
    print_warning "/root/.my.cnf not found. Using /root/my.cnf..."
    cnf="/root/my.cnf"
  else
    print_error "Neither /root/.my.cnf nor /root/my.cnf found."
    return 1
  fi

  MYSQL_CNF="$cnf"
  MYSQL_CMD=(mysql --batch --skip-column-names --defaults-extra-file="$MYSQL_CNF")
  MYSQL_USER="root"

  if ! "${MYSQL_CMD[@]}" -e "SELECT 1;" >/dev/null 2>&1; then
    print_error "Failed to connect to MySQL using cPanel credentials"
    return 1
  fi
  return 0
}

setup_da_mysql() {
  local da_conf="/usr/local/directadmin/conf/mysql.conf"
  [[ -f "$da_conf" ]] || { print_error "DirectAdmin mysql.conf not found at $da_conf"; return 1; }

  local da_user da_pass da_socket
  da_user=$(awk -F= '$1 ~ /^user$/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$da_conf" || true)
  da_pass=$(awk -F= '$1 ~ /^(passwd|password)$/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$da_conf" || true)
  da_socket=$(awk -F= '$1 ~ /^socket$/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$da_conf" || true)

  [[ -n "$da_user" ]] || da_user="da_admin"
  [[ -n "$da_pass" ]] || { print_error "Could not read MySQL password from $da_conf"; return 1; }

  # Create a secure temporary cnf to avoid exposing password in `ps`
  TMP_CNF=$(mktemp /tmp/mysql_killer.XXXXXX.cnf)
  chmod 600 "$TMP_CNF"
  {
    echo "[client]"
    echo "user=$da_user"
    echo "password=$da_pass"
    [[ -n "$da_socket" && -S "$da_socket" ]] && echo "socket=$da_socket"
  } > "$TMP_CNF"

  MYSQL_CMD=(mysql --batch --skip-column-names --defaults-extra-file="$TMP_CNF")
  MYSQL_USER="$da_user"

  if ! "${MYSQL_CMD[@]}" -e "SELECT 1;" >/dev/null 2>&1; then
    print_error "Failed to connect to MySQL using DirectAdmin credentials"
    return 1
  fi
  return 0
}

# -------- Menu --------
show_menu() {
  clear
  echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║   MySQL Process Killer & Monitor v3.1                      ║${NC}"
  echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
  echo
  echo -e "${MAGENTA}${BOLD}📊 Monitoring & Analysis:${NC}"
  echo "  1) Show TOP databases by active query count"
  echo "  2) Show longest running queries (top 20)"
  echo "  3) Show databases by connections count"
  echo "  4) Show detailed database statistics"
  echo "  5) Show TOP users by resource usage"
  echo "  6) Real-time process monitor (auto-refresh)"
  echo "  7) Show server load summary"
  echo
  echo -e "${RED}${BOLD}⚡ Kill Operations:${NC}"
  echo "  8) Kill queries for specific database"
  echo "  9) Show active processes (optional DB filter)"
  echo "  10) Kill long-running queries (>X seconds)"
  echo "  11) Kill all processes for a user"
  echo "  12) Kill specific process by ID"
  echo "  13) Show full processlist"
  echo "  14) Kill all sleeping connections (optional DB filter)"
  echo
  echo -e "${BLUE}${BOLD}🛠️  Advanced:${NC}"
  echo "  15) Export report to file"
  echo "  16) Check slow query log status"
  echo "  17) Show MySQL variables"
  echo "  18) View operation logs"
  echo "  19) Clear logs"
  echo "  20) Exit"
  echo
}

# -------- Monitoring --------
show_top_databases_by_queries() {
  print_header "TOP Databases by Active Query Count"

  local q="
  SELECT
    COALESCE(db, 'NULL') as database_name,
    COUNT(*) as total_processes,
    SUM(command='Query') as active_queries,
    SUM(command='Sleep') as sleeping,
    ROUND(AVG(time), 2) as avg_time,
    MAX(time) as max_time
  FROM information_schema.processlist
  WHERE user != '${MYSQL_USER}'
  GROUP BY db
  ORDER BY active_queries DESC, total_processes DESC
  LIMIT 20;
  "

  echo -e "${BOLD}Database | Total | Active | Sleep | Avg(s) | Max(s)${NC}"
  echo "────────────────────────────────────────────────────────────"
  "${MYSQL_CMD[@]}" -e "$q" 2>/dev/null | while IFS=$'\t' read -r db total active sleep avg_t max_t; do
    local color="$GREEN"
    if (( active > 50 )); then color="${RED}${BOLD}"
    elif (( active > 20 )); then color="$YELLOW"
    elif (( active > 5 )); then color="$CYAN"
    fi
    printf "${color}%-25s${NC} | %-5s | ${color}%-6s${NC} | %-5s | %-6s | %-6s\n" \
      "${db:0:25}" "$total" "$active" "$sleep" "$avg_t" "$max_t"
  done
  echo
}

show_longest_running_queries() {
  print_header "Longest Running Queries (Top 20)"

  # Avoid ONLY_FULL_GROUP_BY issues: select actual rows, order by time
  local q="
  SELECT
    id, user, host, COALESCE(db,'NULL') as db, time, COALESCE(state,'') as state,
    LEFT(COALESCE(info,''), 120) as query_sample
  FROM information_schema.processlist
  WHERE command='Query' AND user != '${MYSQL_USER}'
  ORDER BY time DESC
  LIMIT 20;
  "

  echo -e "${BOLD}ID | User | DB | Time(s) | State | Query Sample${NC}"
  echo "────────────────────────────────────────────────────────────"
  "${MYSQL_CMD[@]}" -e "$q" 2>/dev/null | safe_table
  echo
}

show_databases_by_connections() {
  print_header "Databases by Connection Count"

  local q="
  SELECT
    COALESCE(db, 'NULL') as database_name,
    COUNT(*) as total_connections,
    COUNT(DISTINCT user) as unique_users,
    SUM(command='Sleep') as idle_connections
  FROM information_schema.processlist
  WHERE user != '${MYSQL_USER}'
  GROUP BY db
  ORDER BY total_connections DESC
  LIMIT 20;
  "

  echo -e "${BOLD}Database | Connections | Users | Idle${NC}"
  echo "────────────────────────────────────────────────────────────"
  "${MYSQL_CMD[@]}" -e "$q" 2>/dev/null | safe_table
  echo
}

show_database_detailed_stats() {
  read -rp "Enter database name: " dbname
  [[ -n "$dbname" ]] || { print_error "Database name required."; return; }
  is_mysql_ident "$dbname" || { print_error "Invalid database name. Allowed: [A-Za-z0-9_\$]"; return; }

  print_header "Detailed Statistics for DB: $dbname"

  local total sleeping active max_time avg_time
  read -r total sleeping active max_time avg_time < <(
    "${MYSQL_CMD[@]}" -e "
    SELECT
      COUNT(*),
      SUM(command='Sleep'),
      SUM(command='Query'),
      COALESCE(MAX(time),0),
      COALESCE(ROUND(AVG(time),2),0)
    FROM information_schema.processlist
    WHERE db='${dbname}';
    " 2>/dev/null | xargs
  )

  echo -e "${CYAN}Overview:${NC}"
  echo -e "  Total Processes: ${BOLD}${total:-0}${NC}"
  echo -e "  Active Queries:  ${BOLD}${active:-0}${NC}"
  echo -e "  Sleeping:        ${BOLD}${sleeping:-0}${NC}"
  echo -e "  Max Query Time:  ${BOLD}${max_time:-0}s${NC}"
  echo -e "  Avg Query Time:  ${BOLD}${avg_time:-0}s${NC}"
  echo

  echo -e "${CYAN}Users:${NC}"
  "${MYSQL_CMD[@]}" -e "
  SELECT user, COUNT(*) as connections
  FROM information_schema.processlist
  WHERE db='${dbname}'
  GROUP BY user
  ORDER BY connections DESC;
  " 2>/dev/null | safe_table
  echo

  echo -e "${CYAN}Query States:${NC}"
  "${MYSQL_CMD[@]}" -e "
  SELECT COALESCE(state,'NULL') as state, COUNT(*) as cnt
  FROM information_schema.processlist
  WHERE db='${dbname}' AND command='Query'
  GROUP BY state
  ORDER BY cnt DESC;
  " 2>/dev/null | safe_table
  echo

  echo -e "${CYAN}Top 5 Longest Queries:${NC}"
  "${MYSQL_CMD[@]}" -e "
  SELECT id, user, time, LEFT(COALESCE(info,''), 150) as query
  FROM information_schema.processlist
  WHERE db='${dbname}' AND command='Query'
  ORDER BY time DESC
  LIMIT 5;
  " 2>/dev/null | safe_table
  echo
}

show_top_users() {
  print_header "TOP Users by Resource Usage"

  local q="
  SELECT
    user,
    COUNT(*) as total_processes,
    SUM(command='Query') as active_queries,
    SUM(command='Sleep') as sleeping,
    ROUND(AVG(time), 2) as avg_time,
    MAX(time) as max_time,
    COUNT(DISTINCT db) as databases_used
  FROM information_schema.processlist
  WHERE user NOT IN ('${MYSQL_USER}', 'system user')
  GROUP BY user
  ORDER BY active_queries DESC, total_processes DESC
  LIMIT 15;
  "
  "${MYSQL_CMD[@]}" -e "$q" 2>/dev/null | safe_table
  echo
}

realtime_monitor() {
  local refresh_rate=3
  read -rp "Refresh interval in seconds [default: 3]: " input_rate
  [[ -n "${input_rate:-}" ]] && refresh_rate="$input_rate"
  is_int "$refresh_rate" || { print_error "Refresh rate must be an integer."; return; }
  (( refresh_rate >= 1 )) || { print_error "Refresh rate must be >= 1"; return; }

  print_info "Real-time monitor. Press Ctrl+C to stop..."
  sleep 1

  while true; do
    clear
    print_header "Real-Time Monitor - $(date '+%Y-%m-%d %H:%M:%S')"

    local total active sleep max_time
    read -r total active sleep max_time < <(
      "${MYSQL_CMD[@]}" -e "
      SELECT COUNT(*), SUM(command='Query'), SUM(command='Sleep'), COALESCE(MAX(time),0)
      FROM information_schema.processlist;
      " 2>/dev/null | xargs
    )

    echo -e "${BOLD}Summary:${NC} Total: $total | Active: ${YELLOW}$active${NC} | Sleep: $sleep | Max Time: ${RED}${max_time}s${NC}"
    echo

    echo -e "${BOLD}TOP 10 Active Queries:${NC}"
    "${MYSQL_CMD[@]}" -e "
    SELECT id, user, COALESCE(db,'NULL') as db, time, LEFT(COALESCE(info,''), 80) as query
    FROM information_schema.processlist
    WHERE command='Query' AND user != '${MYSQL_USER}'
    ORDER BY time DESC
    LIMIT 10;
    " 2>/dev/null | safe_table

    sleep "$refresh_rate"
  done
}

show_server_summary() {
  print_header "Server Load Summary"

  # Fetch each variable deterministically
  local uptime threads_conn threads_running queries questions
  uptime=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Uptime';" 2>/dev/null || echo 0)
  threads_conn=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Threads_connected';" 2>/dev/null || echo 0)
  threads_running=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Threads_running';" 2>/dev/null || echo 0)
  queries=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Queries';" 2>/dev/null || echo 0)
  questions=$("${MYSQL_CMD[@]}" -e "SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='Questions';" 2>/dev/null || echo 0)

  local uptime_hours=0
  is_int "$uptime" && uptime_hours=$(( uptime / 3600 ))

  echo -e "${CYAN}${BOLD}MySQL Status:${NC}"
  echo -e "  Uptime:            ${BOLD}${uptime_hours} hours${NC}"
  echo -e "  Threads Connected: ${BOLD}${threads_conn}${NC}"
  echo -e "  Threads Running:   ${BOLD}${threads_running}${NC}"
  echo -e "  Questions:         ${BOLD}${questions}${NC}"
  echo -e "  Queries:           ${BOLD}${queries}${NC}"
  echo

  echo -e "${CYAN}${BOLD}Command Summary:${NC}"
  "${MYSQL_CMD[@]}" -e "
  SELECT command, COUNT(*) as cnt, ROUND(AVG(time),2) as avg_time, MAX(time) as max_time
  FROM information_schema.processlist
  GROUP BY command
  ORDER BY cnt DESC;
  " 2>/dev/null | safe_table
  echo

  if command -v uptime >/dev/null 2>&1; then
    echo -e "${CYAN}${BOLD}System Load:${NC}"
    uptime
    echo
  fi
}

show_processlist() {
  local db="${1:-}"
  local q="SELECT id, user, host, COALESCE(db,'NULL') as db, command, time, COALESCE(state,'') as state, LEFT(COALESCE(info,''), 80) as query FROM information_schema.processlist"
  if [[ -n "$db" ]]; then
    is_mysql_ident "$db" || { print_error "Invalid database name."; return; }
    q="$q WHERE db='${db}'"
  fi
  q="$q ORDER BY time DESC;"
  "${MYSQL_CMD[@]}" -e "$q" 2>/dev/null | safe_table
  echo
}

# -------- Kill actions --------
kill_db_queries() {
  local db="$1"
  local command_filter="${2:-Query}"
  is_mysql_ident "$db" || { print_error "Invalid database name."; return; }

  print_info "Searching processes in DB: $db (Command: $command_filter)"
  log_action "INFO" "Search DB=$db Command=$command_filter"

  local ids
  ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE db='${db}' AND command='${command_filter}' AND user != '${MYSQL_USER}';" 2>/dev/null || true)

  if [[ -z "${ids//[[:space:]]/}" ]]; then
    print_warning "No processes found."
    return 0
  fi

  local count
  count=$(grep -c . <<<"$ids" || echo 0)

  read -rp "Found $count process(es). Kill them? (y/n): " confirm
  [[ "$confirm" =~ ^[yY]$ ]] || { print_info "Aborted."; log_action "INFO" "Kill aborted (DB=$db)"; return 0; }

  local killed=0 failed=0
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    if "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1; then
      ((++killed))
      echo -ne "\r${GREEN}[✓]${NC} Killed: $killed/$count"
    else
      ((++failed))
    fi
  done <<< "$ids"
  echo

  print_success "Killed $killed process(es)."
  log_kill_action "Kill DB Queries" "$db" "$killed" "Command=$command_filter Failed=$failed"
  (( failed > 0 )) && print_warning "Failed to kill $failed process(es)."
}

kill_long_queries() {
  local min_time="${1:-60}"
  is_int "$min_time" || { print_error "Min time must be an integer."; return; }

  print_info "Searching queries running longer than ${min_time}s..."
  log_action "INFO" "Search long queries >${min_time}s"

  local ids
  ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE command='Query' AND time > ${min_time} AND user != '${MYSQL_USER}';" 2>/dev/null || true)

  if [[ -z "${ids//[[:space:]]/}" ]]; then
    print_warning "No long-running queries found."
    return 0
  fi

  "${MYSQL_CMD[@]}" -e "
  SELECT id, user, COALESCE(db,'NULL') as db, time, LEFT(COALESCE(info,''), 120)
  FROM information_schema.processlist
  WHERE command='Query' AND time > ${min_time} AND user != '${MYSQL_USER}'
  ORDER BY time DESC;
  " 2>/dev/null | safe_table
  echo

  local count
  count=$(grep -c . <<<"$ids" || echo 0)

  read -rp "Kill $count process(es)? (y/n): " confirm
  [[ "$confirm" =~ ^[yY]$ ]] || { log_action "INFO" "Kill long queries aborted"; return 0; }

  local killed=0
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1 && ((++killed))
  done <<< "$ids"

  print_success "Killed $killed process(es)."
  log_kill_action "Kill Long Queries" "Time>${min_time}s" "$killed" "Threshold=${min_time}"
}

kill_sleeping_connections() {
  local db="${1:-}"
  local where="command='Sleep' AND user != '${MYSQL_USER}'"
  if [[ -n "$db" ]]; then
    is_mysql_ident "$db" || { print_error "Invalid database name."; return; }
    where="$where AND db='${db}'"
  fi

  print_info "Searching sleeping connections..."
  log_action "INFO" "Search sleeping connections DB=${db:-all}"

  local ids
  ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE ${where};" 2>/dev/null || true)

  if [[ -z "${ids//[[:space:]]/}" ]]; then
    print_warning "No sleeping connections found."
    return 0
  fi

  local count
  count=$(grep -c . <<<"$ids" || echo 0)

  read -rp "Found $count sleeping connection(s). Kill them? (y/n): " confirm
  [[ "$confirm" =~ ^[yY]$ ]] || { log_action "INFO" "Kill sleeping aborted"; return 0; }

  local killed=0
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1 && ((++killed))
  done <<< "$ids"

  print_success "Killed $killed sleeping connection(s)."
  log_kill_action "Kill Sleeping" "${db:-all}" "$killed" "Command=Sleep"
}

kill_user_queries() {
  local username="$1"
  is_mysql_ident "$username" || { print_error "Invalid username."; return; }

  print_info "Searching processes for user: $username"
  log_action "INFO" "Search user=$username"

  local ids
  ids=$("${MYSQL_CMD[@]}" -e "SELECT id FROM information_schema.processlist WHERE user='${username}' AND user != '${MYSQL_USER}';" 2>/dev/null || true)

  if [[ -z "${ids//[[:space:]]/}" ]]; then
    print_warning "No processes found."
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
  count=$(grep -c . <<<"$ids" || echo 0)
  read -rp "Kill $count process(es) for user '$username'? (y/n): " confirm
  [[ "$confirm" =~ ^[yY]$ ]] || { log_action "INFO" "Kill user aborted"; return 0; }

  local killed=0
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    "${MYSQL_CMD[@]}" -e "KILL $id;" >/dev/null 2>&1 && ((++killed))
  done <<< "$ids"

  print_success "Killed $killed process(es)."
  log_kill_action "Kill User Processes" "$username" "$killed" "User=$username"
}

kill_specific_process() {
  local pid="$1"
  is_int "$pid" || { print_error "Process ID must be numeric."; return 1; }

  local exists
  exists=$("${MYSQL_CMD[@]}" -e "SELECT COUNT(*) FROM information_schema.processlist WHERE id=${pid};" 2>/dev/null || echo "0")
  [[ "$exists" != "0" ]] || { print_error "Process ID $pid not found."; return 1; }

  print_info "Process details:"
  "${MYSQL_CMD[@]}" -e "SELECT * FROM information_schema.processlist WHERE id=${pid}\G" 2>/dev/null || true
  echo

  read -rp "Kill this process? (y/n): " confirm
  [[ "$confirm" =~ ^[yY]$ ]] || { log_action "INFO" "Kill pid=$pid aborted"; return 0; }

  if "${MYSQL_CMD[@]}" -e "KILL ${pid};" >/dev/null 2>&1; then
    print_success "Process $pid killed."
    log_kill_action "Kill Specific PID" "PID:$pid" "1" "PID=$pid"
  else
    print_error "Failed to kill process $pid."
    log_action "ERROR" "Failed to kill pid=$pid"
    return 1
  fi
}

# -------- Advanced --------
export_report() {
  local filename="mysql_report_$(date +%Y%m%d_%H%M%S).txt"
  print_info "Generating report: $filename"
  log_action "INFO" "Export report $filename"

  {
    echo "======================================================================"
    echo "MySQL Server Report"
    echo "Generated: $(date)"
    echo "======================================================================"
    echo
    echo "=== Server Summary ==="
    show_server_summary
    echo
    echo "=== TOP Databases ==="
    show_top_databases_by_queries
    echo
    echo "=== Longest Queries ==="
    show_longest_running_queries
    echo
    echo "=== Full Processlist ==="
    show_processlist
  } > "$filename" 2>/dev/null || { print_error "Failed to write report file."; return 1; }

  print_success "Report saved to: $filename"
}

check_slow_query_log() {
  print_header "Slow Query Log Status"
  "${MYSQL_CMD[@]}" -e "
  SELECT VARIABLE_NAME, VARIABLE_VALUE
  FROM information_schema.GLOBAL_VARIABLES
  WHERE VARIABLE_NAME IN ('slow_query_log', 'slow_query_log_file', 'long_query_time');
  " 2>/dev/null | safe_table
  echo
}

show_mysql_variables() {
  print_header "Important MySQL Variables"
  "${MYSQL_CMD[@]}" -e "
  SELECT VARIABLE_NAME, VARIABLE_VALUE
  FROM information_schema.GLOBAL_VARIABLES
  WHERE VARIABLE_NAME IN (
    'max_connections','max_user_connections','wait_timeout','interactive_timeout',
    'max_allowed_packet','thread_cache_size','table_open_cache','innodb_buffer_pool_size',
    'query_cache_size','tmp_table_size','max_heap_table_size'
  )
  ORDER BY VARIABLE_NAME;
  " 2>/dev/null | safe_table
  echo
}

view_logs() {
  print_header "Operation Logs"
  if [[ "$LOG_FILE" == "/dev/null" || ! -f "$LOG_FILE" ]]; then
    print_warning "Logging is disabled or log file not found."
    return
  fi

  local lines=50
  read -rp "Show last N lines [default: 50]: " input
  [[ -n "${input:-}" ]] && lines="$input"
  is_int "$lines" || lines=50

  tail -n "$lines" "$LOG_FILE" 2>/dev/null || print_warning "Cannot read log file."
  echo
}

clear_logs() {
  [[ "$LOG_FILE" != "/dev/null" && -f "$LOG_FILE" ]] || { print_warning "No log file found."; return; }
  read -rp "This will clear ALL logs. Continue? (y/n): " confirm
  [[ "$confirm" =~ ^[yY]$ ]] || { print_info "Cancelled."; return; }
  : > "$LOG_FILE"
  print_success "Logs cleared."
  log_action "INFO" "Logs cleared by user"
}

# -------- Main --------
main() {
  init_logging || true
  [[ "$LOG_FILE" != "/dev/null" ]] && print_success "Logging enabled: $LOG_FILE"

  log_action "INFO" "========== Script Started =========="

  local panel
  panel=$(detect_panel)
  if [[ "$panel" == "unknown" ]]; then
    print_error "Could not detect cPanel or DirectAdmin."
    log_action "ERROR" "Panel detection failed"
    exit 1
  fi

  print_success "Detected control panel: $panel"
  if [[ "$panel" == "cpanel" ]]; then
    setup_cpanel_mysql || exit 2
  else
    setup_da_mysql || exit 2
  fi

  print_success "MySQL connection configured (User: $MYSQL_USER)"
  log_action "INFO" "MySQL connected as $MYSQL_USER"

  while true; do
    show_menu
    read -rp "Select an option [1-20]: " choice
    echo
    case "$choice" in
      1) show_top_databases_by_queries ;;
      2) show_longest_running_queries ;;
      3) show_databases_by_connections ;;
      4) show_database_detailed_stats ;;
      5) show_top_users ;;
      6) realtime_monitor ;;
      7) show_server_summary ;;
      8)
        read -rp "Enter database name: " dbname
        [[ -n "$dbname" ]] || { print_error "Database name required."; continue; }
        kill_db_queries "$dbname" "Query"
        ;;
      9)
        read -rp "Enter database name (or press Enter for all): " dbname
        show_processlist "${dbname:-}"
        ;;
      10)
        read -rp "Enter minimum time in seconds [default: 60]: " min_time
        min_time="${min_time:-60}"
        kill_long_queries "$min_time"
        ;;
      11)
        read -rp "Enter username: " username
        [[ -n "$username" ]] || { print_error "Username required."; continue; }
        kill_user_queries "$username"
        ;;
      12)
        read -rp "Enter process ID: " pid
        [[ -n "$pid" ]] || { print_error "Process ID required."; continue; }
        kill_specific_process "$pid"
        ;;
      13) show_processlist ;;
      14)
        read -rp "Enter database name (or press Enter for all): " dbname
        kill_sleeping_connections "${dbname:-}"
        ;;
      15) export_report ;;
      16) check_slow_query_log ;;
      17) show_mysql_variables ;;
      18) view_logs ;;
      19) clear_logs ;;
      20)
        print_info "Exiting..."
        log_action "INFO" "========== Script Ended =========="
        exit 0
        ;;
      *) print_error "Invalid option. Please select 1-20." ;;
    esac

    echo
    read -rp "Press Enter to continue..."
  done
}

main
