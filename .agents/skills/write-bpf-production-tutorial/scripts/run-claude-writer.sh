#!/usr/bin/env bash
set -euo pipefail

readonly MODEL='claude-opus-4-6[1m]'
readonly SKILL_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly VERIFY="$SKILL_DIR/scripts/verify_claude_trace.py"
readonly GUIDE="$SKILL_DIR/references/writing-guide.md"

usage() {
  echo "usage: $0 --repo ABSOLUTE_REPO_PATH --task ABSOLUTE_TASK_FILE" >&2
}

repo=
task=
while (($#)); do
  case "$1" in
    --repo)
      repo=${2:-}
      shift 2
      ;;
    --task)
      task=${2:-}
      shift 2
      ;;
    --model|--fallback-model)
      echo "model overrides and fallbacks are forbidden; required model: $MODEL" >&2
      exit 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ $repo = /* && -d $repo/.git ]] || { echo "--repo must be an absolute Git checkout" >&2; exit 2; }
[[ $task = /* && -f $task ]] || { echo "--task must be an absolute readable file" >&2; exit 2; }
command -v claude >/dev/null || { echo "Claude Code is required" >&2; exit 127; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 127; }

state_root=${XDG_STATE_HOME:-$HOME/.local/state}/bpf-tutorial-writer/runs
mkdir -p "$state_root"
chmod 700 "$state_root"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
run_dir="$state_root/$run_id"
mkdir -m 700 "$run_dir"
trace="$run_dir/claude-trace.jsonl"
manifest="$run_dir/manifest.json"

head_before=$(git -C "$repo" rev-parse HEAD)
status_before=$(git -C "$repo" status --porcelain=v1)
task_sha=$(sha256sum "$task" | awk '{print $1}')

prompt=$(printf '%s\n\n%s\n\n%s\n' \
  'You are the sole prose author for an eBPF production tutorial. Read the repository code and evidence named in the task. Edit only the README.md and README.zh.md paths explicitly allowed by the task. Do not edit code, build files, generated indexes, or tests. Do not invent output or claims. Finish by stating which README files you edited.' \
  "$(<"$GUIDE")" \
  "$(<"$task")")

set +e
(
  cd "$repo"
  claude -p \
    --model "$MODEL" \
    --effort high \
    --permission-mode acceptEdits \
    --allowedTools Read Edit Write \
    --output-format stream-json \
    --verbose \
    "$prompt"
) >"$trace" 2>&1
claude_status=$?
set -e

trace_sha=$(sha256sum "$trace" | awk '{print $1}')
head_after=$(git -C "$repo" rev-parse HEAD)
status_after=$(git -C "$repo" status --porcelain=v1)

MODEL_VALUE="$MODEL" \
REPO_VALUE="$repo" \
TASK_VALUE="$task" \
TASK_SHA_VALUE="$task_sha" \
TRACE_VALUE="$trace" \
TRACE_SHA_VALUE="$trace_sha" \
CLAUDE_STATUS_VALUE="$claude_status" \
HEAD_BEFORE_VALUE="$head_before" \
HEAD_AFTER_VALUE="$head_after" \
STATUS_BEFORE_VALUE="$status_before" \
STATUS_AFTER_VALUE="$status_after" \
python3 - "$manifest" <<'PY'
import json
import os
import pathlib

path = pathlib.Path(__import__("sys").argv[1])
path.write_text(json.dumps({
    "model": os.environ["MODEL_VALUE"],
    "repo": os.environ["REPO_VALUE"],
    "task": os.environ["TASK_VALUE"],
    "task_sha256": os.environ["TASK_SHA_VALUE"],
    "trace": os.environ["TRACE_VALUE"],
    "trace_sha256": os.environ["TRACE_SHA_VALUE"],
    "claude_exit_status": int(os.environ["CLAUDE_STATUS_VALUE"]),
    "head_before": os.environ["HEAD_BEFORE_VALUE"],
    "head_after": os.environ["HEAD_AFTER_VALUE"],
    "status_before": os.environ["STATUS_BEFORE_VALUE"],
    "status_after": os.environ["STATUS_AFTER_VALUE"],
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
chmod 600 "$trace" "$manifest"

if ((claude_status != 0)); then
  echo "Claude exited with status $claude_status; preserved trace: $trace" >&2
  exit "$claude_status"
fi

python3 "$VERIFY" --trace "$trace" --model "$MODEL" --require-write
echo "manifest=$manifest"
