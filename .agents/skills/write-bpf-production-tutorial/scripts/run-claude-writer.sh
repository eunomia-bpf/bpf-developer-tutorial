#!/usr/bin/env bash
set -euo pipefail

readonly MODEL='claude-opus-4-6[1m]'
readonly SKILL_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly VERIFY="$SKILL_DIR/scripts/verify_claude_trace.py"
readonly GUIDE="$SKILL_DIR/references/drafting-process.md"
readonly PRECEDENTS="$SKILL_DIR/references/repository-precedents.md"
readonly STYLE_DIR="$SKILL_DIR/../bpf-tutorial-writing-style"
readonly STYLE_GUIDELINES="$STYLE_DIR/references/advanced-tutorial-guidelines.md"
readonly STYLE_REPOSITORY="$STYLE_DIR/references/repository-house-style.md"
readonly STYLE_PROSE="$STYLE_DIR/references/prose-and-bilingual-checklist.md"

usage() {
  echo "usage: $0 --repo ABSOLUTE_REPO_PATH --task ABSOLUTE_TASK_FILE --readme ABSOLUTE_README_PATH --readme ABSOLUTE_README_PATH" >&2
}

repo=
task=
declare -a readmes=()
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
    --readme)
      readmes+=("${2:-}")
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

command -v claude >/dev/null || { echo "Claude Code is required" >&2; exit 127; }
command -v git >/dev/null || { echo "git is required" >&2; exit 127; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 127; }
command -v realpath >/dev/null || { echo "realpath is required" >&2; exit 127; }
[[ $repo = /* && -d $repo ]] || { echo "--repo must be an absolute directory" >&2; exit 2; }
repo=$(realpath -e -- "$repo")
[[ $(git -C "$repo" rev-parse --is-inside-work-tree 2>/dev/null) == true ]] || {
  echo "--repo must be a Git worktree" >&2
  exit 2
}
[[ $task = /* && -f $task ]] || { echo "--task must be an absolute readable file" >&2; exit 2; }
task=$(realpath -e -- "$task")
((${#readmes[@]} == 2)) || { echo "pass exactly two --readme paths" >&2; exit 2; }

declare -a allowed_readmes=()
english_readme=
chinese_readme=
for readme in "${readmes[@]}"; do
  [[ $readme = /* ]] || { echo "--readme must be absolute: $readme" >&2; exit 2; }
  readme=$(realpath -m -- "$readme")
  case "$readme" in
    "$repo"/src/*/README.md)
      [[ -z $english_readme ]] || { echo "pass only one README.md" >&2; exit 2; }
      english_readme=$readme
      ;;
    "$repo"/src/*/README.zh.md)
      [[ -z $chinese_readme ]] || { echo "pass only one README.zh.md" >&2; exit 2; }
      chinese_readme=$readme
      ;;
    *) echo "--readme must name a tutorial README inside $repo/src: $readme" >&2; exit 2 ;;
  esac
  allowed_readmes+=("$readme")
done
[[ -n $english_readme && -n $chinese_readme && $(dirname -- "$english_readme") == $(dirname -- "$chinese_readme") ]] || {
  echo "--readme paths must be the English and Chinese pair from one lesson" >&2
  exit 2
}

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
printf -v allowed_paths 'Allowed README path: %s\n' "${allowed_readmes[@]}"

prompt=$(printf '%s\n\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
  'You are the prose author for this eBPF production tutorial pass. Read the repository code and evidence named in the task. Edit only the README.md and README.zh.md paths explicitly allowed by the task. Do not edit code, build files, generated indexes, or tests. Do not invent output or claims. Finish by stating which README files you edited.' \
  "$allowed_paths" \
  "$(<"$GUIDE")" \
  "$(<"$PRECEDENTS")" \
  "$(<"$STYLE_GUIDELINES")" \
  "$(<"$STYLE_REPOSITORY")" \
  "$(<"$STYLE_PROSE")" \
  "$(<"$task")")

set +e
(
  cd "$repo"
  claude -p \
    --safe-mode \
    --model "$MODEL" \
    --effort high \
    --permission-mode acceptEdits \
    --tools "Read,Edit,Write" \
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
if [[ $head_after != "$head_before" ]]; then
  echo "Claude changed Git HEAD; preserved trace: $trace" >&2
  exit 1
fi

verify_args=(--trace "$trace" --model "$MODEL" --repo "$repo" --require-write)
for readme in "${allowed_readmes[@]}"; do
  verify_args+=(--allowed-path "$readme")
done
python3 "$VERIFY" "${verify_args[@]}"
echo "manifest=$manifest"
