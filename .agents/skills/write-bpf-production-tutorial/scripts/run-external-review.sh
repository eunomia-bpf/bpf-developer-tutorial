#!/usr/bin/env bash
set -euo pipefail

readonly SKILL_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly WRITING_GUIDE="$SKILL_DIR/references/writing-guide.md"
readonly REVIEW_GUIDE="$SKILL_DIR/references/review-checklist.md"
readonly PRECEDENT_GUIDE="$SKILL_DIR/references/repository-precedents.md"

usage() {
  echo "usage: $0 --reviewer grok|glm --repo ABSOLUTE_REPO_PATH --task ABSOLUTE_TASK_FILE --file REPO_RELATIVE_PATH [--file ...]" >&2
}

reviewer=
repo=
task=
files=()
while (($#)); do
  case "$1" in
    --reviewer)
      reviewer=${2:-}
      shift 2
      ;;
    --repo)
      repo=${2:-}
      shift 2
      ;;
    --task)
      task=${2:-}
      shift 2
      ;;
    --file)
      files+=("${2:-}")
      shift 2
      ;;
    --model|--fallback-model)
      echo "model overrides and fallbacks are forbidden" >&2
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

[[ $reviewer == grok || $reviewer == glm ]] || { usage; exit 2; }
[[ $repo = /* && -d $repo ]] || { echo "--repo must be an absolute Git checkout" >&2; exit 2; }
git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "--repo must be an absolute Git checkout" >&2; exit 2; }
[[ $task = /* && -f $task ]] || { echo "--task must be an absolute readable file" >&2; exit 2; }
((${#files[@]} >= 2)) || { echo "pass at least the English and Chinese README with --file" >&2; exit 2; }
command -v git >/dev/null || { echo "git is required" >&2; exit 127; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 127; }

case "$reviewer" in
  grok)
    readonly model='grok-4.5'
    command -v grok >/dev/null || { echo "Grok CLI is required" >&2; exit 127; }
    ;;
  glm)
    readonly model='zai-coding-plan/glm-5.2'
    command -v opencode >/dev/null || { echo "OpenCode is required" >&2; exit 127; }
    ;;
esac

repo_real=$(realpath "$repo")
for file in "${files[@]}"; do
  [[ $file && $file != /* ]] || { echo "--file paths must be repository-relative: $file" >&2; exit 2; }
  file_real=$(realpath "$repo/$file")
  [[ $file_real == "$repo_real"/* && -f $file_real ]] || { echo "invalid review file: $file" >&2; exit 2; }
done

state_root=${XDG_STATE_HOME:-$HOME/.local/state}/bpf-tutorial-reviews/runs
mkdir -p "$state_root"
chmod 700 "$state_root"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$-$reviewer"
run_dir="$state_root/$run_id"
mkdir -m 700 "$run_dir"
prompt="$run_dir/review-prompt.md"
trace="$run_dir/review-trace.jsonl"
manifest="$run_dir/manifest.json"

{
  printf '# Independent eBPF tutorial review\n\n'
  printf 'Review this immutable snapshot. Do not edit files, run commands, use network sources, or infer facts absent from the snapshot. Do not assume the author\x27s intended diagnosis.\n\n'
  printf '## Writing rulebook\n\n'
  sed -n '1,$p' "$WRITING_GUIDE"
  printf '\n## Review rulebook\n\n'
  sed -n '1,$p' "$REVIEW_GUIDE"
  printf '\n## Repository precedent rulebook\n\n'
  sed -n '1,$p' "$PRECEDENT_GUIDE"
  printf '\n## Review task and evidence\n\n'
  sed -n '1,$p' "$task"
  for file in "${files[@]}"; do
    printf '\n## Snapshot: `%s`\n\n```text\n' "$file"
    sed -n '1,$p' "$repo/$file"
    printf '\n```\n'
  done
} >"$prompt"
chmod 600 "$prompt"

head_before=$(git -C "$repo" rev-parse HEAD)
status_before=$(git -C "$repo" status --porcelain=v1)
files_before=$(
  for file in "${files[@]}"; do
    sha256sum "$repo/$file"
  done
)
prompt_sha=$(sha256sum "$prompt" | awk '{print $1}')

set +e
case "$reviewer" in
  grok)
    (
      cd "$run_dir"
      grok --prompt-file "$prompt" \
        --model "$model" \
        --permission-mode plan \
        --no-subagents \
        --disable-web-search \
        --output-format streaming-json
    ) >"$trace" 2>&1
    review_status=$?
    ;;
  glm)
    (
      cd "$run_dir"
      opencode run \
        'Review the complete attached snapshot and return only the requested independent review.' \
        --dir "$run_dir" \
        --model "$model" \
        --agent plan \
        --format json \
        --title "bpf-tutorial-review-$run_id" \
        --file "$prompt"
    ) >"$trace" 2>&1
    review_status=$?
    ;;
esac
set -e

trace_sha=$(sha256sum "$trace" | awk '{print $1}')
head_after=$(git -C "$repo" rev-parse HEAD)
status_after=$(git -C "$repo" status --porcelain=v1)
files_after=$(
  for file in "${files[@]}"; do
    sha256sum "$repo/$file"
  done
)

REVIEWER_VALUE="$reviewer" \
MODEL_VALUE="$model" \
REPO_VALUE="$repo" \
TASK_VALUE="$task" \
PROMPT_VALUE="$prompt" \
PROMPT_SHA_VALUE="$prompt_sha" \
TRACE_VALUE="$trace" \
TRACE_SHA_VALUE="$trace_sha" \
REVIEW_STATUS_VALUE="$review_status" \
HEAD_BEFORE_VALUE="$head_before" \
HEAD_AFTER_VALUE="$head_after" \
STATUS_BEFORE_VALUE="$status_before" \
STATUS_AFTER_VALUE="$status_after" \
FILES_BEFORE_VALUE="$files_before" \
FILES_AFTER_VALUE="$files_after" \
python3 - "$manifest" <<'PY'
import json
import os
import pathlib

path = pathlib.Path(__import__("sys").argv[1])
path.write_text(json.dumps({
    "reviewer": os.environ["REVIEWER_VALUE"],
    "model": os.environ["MODEL_VALUE"],
    "repo": os.environ["REPO_VALUE"],
    "task": os.environ["TASK_VALUE"],
    "prompt": os.environ["PROMPT_VALUE"],
    "prompt_sha256": os.environ["PROMPT_SHA_VALUE"],
    "trace": os.environ["TRACE_VALUE"],
    "trace_sha256": os.environ["TRACE_SHA_VALUE"],
    "review_exit_status": int(os.environ["REVIEW_STATUS_VALUE"]),
    "head_before": os.environ["HEAD_BEFORE_VALUE"],
    "head_after": os.environ["HEAD_AFTER_VALUE"],
    "status_before": os.environ["STATUS_BEFORE_VALUE"],
    "status_after": os.environ["STATUS_AFTER_VALUE"],
    "repository_status_changed": os.environ["STATUS_BEFORE_VALUE"] != os.environ["STATUS_AFTER_VALUE"],
    "review_files_sha256_before": os.environ["FILES_BEFORE_VALUE"].splitlines(),
    "review_files_sha256_after": os.environ["FILES_AFTER_VALUE"].splitlines(),
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
chmod 600 "$trace" "$manifest"

if ((review_status != 0)); then
  echo "$reviewer exited with status $review_status; preserved trace: $trace" >&2
  exit "$review_status"
fi
[[ -s $trace ]] || { echo "review trace is empty: $trace" >&2; exit 1; }
if [[ $head_before != "$head_after" || $files_before != "$files_after" ]]; then
  echo "read-only review changed Git HEAD or a reviewed file; preserved trace: $trace" >&2
  exit 1
fi
if [[ $status_before != "$status_after" ]]; then
  echo "warning: unrelated repository status changed during review; recorded in manifest" >&2
fi

echo "manifest=$manifest"
