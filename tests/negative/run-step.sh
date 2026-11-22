#!/usr/bin/env bash
# Runs one step of the shared security baseline outside GitHub Actions, so self-check can feed it input it must
# reject. The step's script is read from the workflow file itself (with yq), so the test exercises the text that
# callers run, not a copy of it. The workflow-level env (scanner versions and SHA-256 pins) is exported first.
#
# Usage: run-step.sh <job-id> <step name>
# Env:   BASELINE_WORKFLOW  path to security-baseline.yml (required)
#        plus whatever the step reads from its own env block (SCAN_PATH, SEVERITY, ...), set by the caller.
set -euo pipefail

wf="${BASELINE_WORKFLOW:?set BASELINE_WORKFLOW to the path of security-baseline.yml}"
if [ "$#" -ne 2 ]; then
  echo "usage: run-step.sh <job-id> <step name>" >&2
  exit 2
fi

script="$(JOB="$1" NAME="$2" yq '.jobs[strenv(JOB)].steps[] | select(.name == strenv(NAME)) | .run' "$wf")"
if [ -z "$script" ] || [ "$script" = null ]; then
  echo "run-step.sh: no step named '$2' with a run script in job '$1' of $wf" >&2
  exit 2
fi
envs="$(yq -o=shell '.env' "$wf")"
set -a
eval "$envs"
set +a
# GitHub runs a step with no shell: key as bash -e.
exec bash -e -c "$script"
