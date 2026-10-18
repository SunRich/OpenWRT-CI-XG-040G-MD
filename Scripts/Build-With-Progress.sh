#!/bin/bash
# Keep long toolchain builds observable without printing environment secrets.
set -euo pipefail

progress() {
	while true; do
		echo "Build progress: $(date -u +%FT%TZ)"
		# Command names only: process arguments can contain credentials.
		ps -eo pid,ppid,stat,pcpu,pmem,etime,comm --sort=-pcpu | head -n 12 || true
		df -h .
		for log in logs/tools/cmake/compile.txt logs/tools/cmake/configure.txt; do
			if [[ -f "$log" ]]; then
				echo "$log"
				tail -n 8 "$log"
			fi
		done
		sleep 45
	done
}

progress &
progress_pid=$!
trap 'kill "$progress_pid" 2>/dev/null || true; wait "$progress_pid" 2>/dev/null || true' EXIT

make -j"${1:-2}" BUILD_LOG=1 || make -j1 V=s BUILD_LOG=1
