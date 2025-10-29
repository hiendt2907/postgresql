#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

: "${REPMGR_CONF:=/etc/repmgr/repmgr.conf}"
: "${NODE_NAME:=$(hostname)}"
: "${PGDATA:=/var/lib/postgresql/data}"
: "${LAST_PRIMARY_FILE:="$PGDATA/last_known_primary"}"
: "${EVENT_INTERVAL:=15}"       # check event mỗi 15s
: "${HEALTH_INTERVAL:=60}"      # healthcheck mỗi 60s
: "${REFRESH_INTERVAL:=5}"      # refresh last_known_primary mỗi 5s

log() { echo "[$(date -Iseconds)] [monitor] $*"; }

# Atomic write for last-known-primary (tmp+mv)
function write_last_primary() {
  local primary="$1"
  local tmp="${LAST_PRIMARY_FILE}.tmp"
  printf "%s\n" "$primary" > "$tmp"
  chmod 600 "$tmp" 2>/dev/null || true
  chown postgres:postgres "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$LAST_PRIMARY_FILE"
  sync
  chmod 600 "$LAST_PRIMARY_FILE" 2>/dev/null || true
  chown postgres:postgres "$LAST_PRIMARY_FILE" 2>/dev/null || true
}

trim() {
  local s="${1:-}"
  echo "$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<< "$s")"
}

normalize_status() {
  local s; s="$(trim "${1:-}")"
  s="${s#* }"
  s="$(echo "$s" | tr '[:upper:]' '[:lower:]')"
  echo "$s"
}

function get_current_primary() {
  # First check local node status to see if we are primary
  local local_role=$(gosu postgres repmgr -f "$REPMGR_CONF" node status 2>/dev/null | grep -i '^role' | cut -d':' -f2 | tr -d ' ' || echo "")
  if [ "$local_role" = "primary" ]; then
    # If we are primary, return our own node name
    echo "$NODE_NAME"
    return
  fi
  
  # If we are not primary, check repmgr cluster status
  local result=""
  result=$(gosu postgres repmgr -f "$REPMGR_CONF" node status 2>/dev/null | grep -i 'primary node' | cut -d':' -f2 | tr -d ' ' || true)
  if [ -n "$result" ]; then
    echo "$result"
    return
  fi
  
  # Fallback to cluster show if node status doesn't give us the primary
  result=$(gosu postgres repmgr -f "$REPMGR_CONF" cluster show 2>/dev/null | grep -i 'primary' | cut -d'|' -f2 | tr -d '* ' || true)
  echo "$result"
}

check_cluster_health() {
  local status total_nodes=0 online_nodes=0
  status=$(gosu postgres repmgr -f "$REPMGR_CONF" cluster show --csv 2>/dev/null || true)

  if [ -z "$status" ]; then
    echo "UNKNOWN"
    return
  fi

  # CSV format: node_id,role_code,status_code
  # role_code: 0=primary, 1=standby, 2=witness
  # status_code: 0=down, 1=running
  while IFS=',' read -r node_id role_code status_code; do
    node_id="$(trim "$node_id")"
    role_code="$(trim "$role_code")"
    status_code="$(trim "$status_code")"
    
    if ! [[ "$node_id" =~ ^[0-9]+$ ]]; then
      continue
    fi
    
    # Skip witness nodes (role_code=2) from health calculation
    if [ "$role_code" = "2" ]; then
      continue
    fi
    
    total_nodes=$((total_nodes+1))
    
    # status_code: 1 = running
    if [ "$status_code" = "1" ]; then
      online_nodes=$((online_nodes+1))
    fi
  done <<< "$status"

  local quorum=$(( total_nodes/2 + 1 ))

  if [ "$total_nodes" -eq 0 ]; then
    echo "UNKNOWN"
    return
  fi

  if [ "$total_nodes" -eq 1 ] && [ "$online_nodes" -eq 1 ]; then
    echo "GREEN"
    return
  fi

  if [ "$online_nodes" -eq "$total_nodes" ]; then
    echo "GREEN"
  elif [ "$online_nodes" -ge "$quorum" ]; then
    echo "YELLOW"
  elif [ "$online_nodes" -eq 1 ] && [ "$total_nodes" -gt 1 ]; then
    echo "DISASTER"
  else
    echo "RED"
  fi
}

# --- MAIN LOOP ---
last_event_check=0
last_health_check=0
last_refresh=0

# Wait for PostgreSQL to be ready before starting monitoring
log "Waiting for PostgreSQL to be ready..."
while ! gosu postgres pg_isready -h "$NODE_NAME" -p 5432 >/dev/null 2>&1; do
  sleep 2
done
log "PostgreSQL is ready, starting monitoring loops"

while true; do
  now=$(date +%s)
  
  # Check if PostgreSQL is still running
  if ! gosu postgres pg_isready -h "$NODE_NAME" -p 5432 >/dev/null 2>&1; then
    log "[critical] PostgreSQL is not responding, skipping this iteration"
    sleep 5
    continue
  fi

  # --- Refresh layer ---
  if (( now - last_refresh >= REFRESH_INTERVAL )); then
    last_refresh=$now
    current_primary="$(get_current_primary)"
    if [ -n "$current_primary" ]; then
      write_last_primary "$current_primary"
      # Only log if primary changed
      if [ -f "$LAST_PRIMARY_FILE" ]; then
        prev_primary=$(tail -n 1 "$LAST_PRIMARY_FILE" 2>/dev/null || echo "")
        if [ "$prev_primary" != "$current_primary" ]; then
          log "[refresh] Primary changed: $prev_primary → $current_primary"
        fi
      fi
    else
      log "[refresh] WARNING: Primary not determined from cluster show"
    fi
  fi

  # --- Event layer ---
  if (( now - last_event_check >= EVENT_INTERVAL )); then
    last_event_check=$now
    events=$(gosu postgres repmgr -f "$REPMGR_CONF" cluster event --limit=50 2>/dev/null || true)
    
    # Only log if there are failover/promote events
    if echo "$events" | grep -Eiq 'promote|failover'; then
      log "[event] FAILOVER/PROMOTE detected!"
      echo "$events" | grep -Ei 'promote|failover'
      
      cluster_info=$(gosu postgres repmgr -f "$REPMGR_CONF" cluster show --compact 2>/dev/null || true)
      echo "$cluster_info"
      
      # Extract promoted node from events
      promoted_node=$(echo "$events" | grep -m1 'promoted to primary' | grep -o 'node "[^"]*"' | head -1 | cut -d'"' -f2)
      if [ -n "$promoted_node" ]; then
        log "[event] Detected promotion of node $promoted_node → updating last-known-primary"
        write_last_primary "$promoted_node"
      fi

      # Cleanup/rejoin logic
      status=$(gosu postgres repmgr -f "$REPMGR_CONF" cluster show --csv 2>/dev/null || true)
      if [ -n "$status" ]; then
        while IFS=',' read -r node_id node_name role state upstream _; do
          node_id="$(trim "$node_id")"
          node_name="$(trim "$node_name")"
          role="$(normalize_status "$role")"
          state="$(normalize_status "$state")"
          if ! [[ "$node_id" =~ ^[0-9]+$ ]]; then
            continue
          fi

          if [[ "$state" =~ unreachable|failed ]]; then
            log "[event] Detected $node_name (ID:$node_id) is $state"
            if [ "$node_name" = "$NODE_NAME" ] && [ "$role" = "standby" ]; then
              log "[event] This node is standby and unreachable → try rejoin"
              if gosu postgres repmgr -f "$REPMGR_CONF" node rejoin --dry-run; then
                gosu postgres repmgr -f "$REPMGR_CONF" node rejoin --force
                gosu postgres repmgr -f "$REPMGR_CONF" standby register --force
                log "[event] Rejoin successful"
              else
                log "[event] Rejoin not possible, manual clone may be required"
              fi
            else
              log "[event] Cleaning metadata for node $node_name"
              gosu postgres repmgr -f "$REPMGR_CONF" cluster cleanup --node-id="$node_id" || true
            fi
          fi
        done <<< "$status"
      fi
    fi
  fi

  # --- Health layer ---
  if (( now - last_health_check >= HEALTH_INTERVAL )); then
    last_health_check=$now
    health="$(check_cluster_health)"
    
    # Only log if NOT GREEN
    if [ "$health" != "GREEN" ]; then
      confirmed="$health"
      for i in $(seq 1 5); do
        sleep 1
        h2="$(check_cluster_health)"
        if [ "$h2" != "$health" ]; then
          confirmed="FLAPPING"
          break
        fi
      done
      log "[health] ⚠️  Cluster health: $confirmed (NOT GREEN!)"
      gosu postgres repmgr -f "$REPMGR_CONF" cluster show --compact 2>/dev/null || true
    fi
  fi

  sleep 1
done
