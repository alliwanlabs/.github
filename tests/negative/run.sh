#!/usr/bin/env bash
# Proves the checks in security-baseline.yml fail on input they must reject, not only pass on clean input.
# Every case runs a step's own script (tests/negative/run-step.sh) on input built here at run time, so no secret,
# vulnerable lockfile or broken script is ever committed to this repository.
#
# Cases that need only bash, git, gh and python3 always run. The scanner cases (gitleaks, osv-scanner, Semgrep,
# Trivy) download the pinned Linux scanners and need Docker, so they run only with NEGATIVE_SCANNERS=1 (self-check
# sets it). LOCAL_SHELLCHECK=<path> uses that binary in place of the pinned download, for a run on a laptop.
# LOCAL_GITLEAKS=<path> does the same for gitleaks and runs the gitleaks rule cases without the other scanners.
#
# Exit 0 when every case behaved as expected, 1 when any did not (each failure is listed at the end).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
step="$here/run-step.sh"
export BASELINE_WORKFLOW="${BASELINE_WORKFLOW:-$here/../../.github/workflows/security-baseline.yml}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export RUNNER_TEMP="$work/runner-temp"
mkdir -p "$RUNNER_TEMP"
export GITHUB_OUTPUT="$work/github-output" GITHUB_STEP_SUMMARY="$work/step-summary" GITHUB_ENV="$work/github-env"

failures=()

# check <case> <want: 0, nonzero or an exact code> <regex the output must match, or ''> <regex it must not match,
# or ''> <command...>
check() {
  local name="$1" want="$2" must="$3" mustnot="$4" out rc=0 ok=yes
  shift 4
  out="$("$@" 2>&1)" || rc=$?
  case "$want" in
    nonzero) if [ "$rc" -eq 0 ]; then ok=no; fi ;;
    *) if [ "$rc" -ne "$want" ]; then ok=no; fi ;;
  esac
  if [ -n "$must" ] && ! grep -Eiq -- "$must" <<< "$out"; then ok=no; fi
  if [ -n "$mustnot" ] && grep -Eiq -- "$mustnot" <<< "$out"; then ok=no; fi
  if [ "$ok" = yes ]; then
    echo "PASS  $name (exit $rc)"
  else
    echo "FAIL  $name: exit $rc, wanted $want${must:+, output matching /$must/}${mustnot:+, output not matching /$mustnot/}"
    sed 's/^/      /' <<< "$out"
    failures+=("$name")
  fi
}

# new_repo <name>: an empty git repository under the work folder; prints its path.
new_repo() {
  local d="$work/$1"
  mkdir -p "$d"
  git -C "$d" init -q
  git -C "$d" config user.email negative-test@example.invalid
  git -C "$d" config user.name "negative test"
  printf '%s\n' "$d"
}

commit_all() {
  git -C "$1" add -A
  git -C "$1" commit -q -m fixture
}

in_dir() {
  local d="$1"
  shift
  (cd "$d" && "$@")
}

# --- Plan: a pull request whose file list cannot be read runs the heavy scans ---------------------------------
plan_output_heavy() {
  : > "$GITHUB_OUTPUT"
  MODE=auto EVENT=pull_request REF=refs/pull/0/merge DEFAULT_BRANCH=main PR_NUMBER=0 \
    REPO="${GITHUB_REPOSITORY:-alliwanlabs/.github}" DOCKERFILE=Dockerfile \
    "$step" plan "Decide which scans run"
  grep -x 'heavy=.*' "$GITHUB_OUTPUT"
}
check "plan: unreadable pull request file list runs the heavy scans" 0 '^heavy=true$' '^heavy=false$' \
  in_dir "$work" plan_output_heavy

# --- ShellCheck ---------------------------------------------------------------------------------------------
if [ -n "${LOCAL_SHELLCHECK:-}" ]; then
  cp "$LOCAL_SHELLCHECK" "$RUNNER_TEMP/shellcheck"
else
  "$step" shellcheck "Install ShellCheck"
fi

bad="$(new_repo shellcheck-bad)"
mkdir -p "$bad/tools"
printf '#!/usr/bin/env bash\necho "unterminated\n' > "$bad/broken.sh"
printf '#!/bin/sh\necho "unterminated\n' > "$bad/tools/deploy"
# A Python file is not a shell script, whatever it contains.
printf '#!/usr/bin/env python3\necho "unterminated\n' > "$bad/tools/script.py"
commit_all "$bad"
check "shellcheck: errors in a .sh file and in a sh-shebang file fail the check" nonzero \
  'broken\.sh' 'script\.py' \
  in_dir "$bad" env SCAN_PATH=. SEVERITY=error "$step" shellcheck "Check shell scripts"
check "shellcheck: the shebang-only file is checked" nonzero 'tools/deploy' '' \
  in_dir "$bad" env SCAN_PATH=tools SEVERITY=error "$step" shellcheck "Check shell scripts"

good="$(new_repo shellcheck-good)"
printf '#!/usr/bin/env bash\nset -euo pipefail\necho "ok"\n' > "$good/ok.sh"
commit_all "$good"
check "shellcheck: a clean script passes" 0 '' '' \
  in_dir "$good" env SCAN_PATH=. SEVERITY=error "$step" shellcheck "Check shell scripts"

none="$(new_repo shellcheck-none)"
printf 'print("no shell here")\n' > "$none/app.py"
commit_all "$none"
check "shellcheck: no shell script passes with a notice" 0 '::notice title=No shell scripts' '' \
  in_dir "$none" env SCAN_PATH=. SEVERITY=error "$step" shellcheck "Check shell scripts"
check "shellcheck: an unknown severity fails" nonzero 'shellcheck-severity must be' '' \
  in_dir "$none" env SCAN_PATH=. SEVERITY=fatal "$step" shellcheck "Check shell scripts"

# --- Vendored-file integrity ----------------------------------------------------------------------------------
vend="$(new_repo vendored)"
mkdir -p "$vend/src/kit"
printf 'export const x = 1;\n' > "$vend/src/kit/x.js"
sum="$(python3 -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$vend/src/kit/x.js")"
printf '{"files": {"x.js": "%s"}}\n' "$sum" > "$vend/src/kit/VENDORED.json"
commit_all "$vend"
check "vendored: an unchanged copy passes" 0 'checked=1 problems=0' '' \
  in_dir "$vend" "$step" vendored "Check vendored files against their manifests"
printf 'export const x = 2;\n' > "$vend/src/kit/x.js"
check "vendored: a hand-edited copy fails" 1 'EDITED +src/kit/x\.js' '' \
  in_dir "$vend" "$step" vendored "Check vendored files against their manifests"
git -C "$vend" checkout -q -- src/kit/x.js
rm "$vend/src/kit/x.js"
check "vendored: a deleted copy fails" 1 'MISSING +src/kit/x\.js' '' \
  in_dir "$vend" "$step" vendored "Check vendored files against their manifests"
git -C "$vend" checkout -q -- src/kit/x.js
printf '{"files": ' > "$vend/src/kit/VENDORED.json"
check "vendored: an unreadable manifest fails" 2 'UNREADABLE' '' \
  in_dir "$vend" "$step" vendored "Check vendored files against their manifests"
check "vendored: no manifest passes with a notice" 0 '::notice title=No vendoring manifest' '' \
  in_dir "$none" "$step" vendored "Check vendored files against their manifests"

# --- Scanners -------------------------------------------------------------------------------------------------
if [ "${NEGATIVE_SCANNERS:-0}" = 1 ]; then
  "$step" gitleaks "Install gitleaks"
  "$step" osv "Install osv-scanner"
  "$step" trivy-fs "Install Trivy"

  leak="$(new_repo gitleaks-leak)"
  # A token in the GitHub personal access token format, made up at run time; it was never issued.
  printf 'token = "ghp_%s"\n' "$(openssl rand -hex 18)" > "$leak/config.py"
  commit_all "$leak"
  check "gitleaks: a committed token fails" nonzero 'leaks found' '' \
    in_dir "$leak" env CONFIG= "$step" gitleaks "Scan the whole history"

  vuln="$(new_repo vulnerable)"
  # Django 3.2.0 has many published, fixed advisories.
  printf 'django==3.2.0\n' > "$vuln/requirements.txt"
  printf 'import hashlib\nimport pickle\nimport subprocess\nimport sys\n\nsubprocess.call(sys.argv[1], shell=True)\neval(sys.argv[2])\npickle.loads(sys.stdin.buffer.read())\nhashlib.md5(b"x")\n' \
    > "$vuln/app.py"
  commit_all "$vuln"
  check "osv-scanner: a vulnerable pinned package fails" nonzero 'django' '' \
    in_dir "$vuln" env SCAN_PATH=. "$step" osv "Scan lockfiles"
  check "trivy fs: a vulnerable pinned package fails" nonzero 'django' '' \
    in_dir "$vuln" env SCAN_PATH=. SEVERITY=HIGH,CRITICAL "$step" trivy-fs "Scan vulnerabilities and misconfiguration"
  # Exit 1 is "findings" under --error; Semgrep's own errors exit 2 or more, so they cannot pass this case.
  check "semgrep: findings fail the check" 1 '' '' \
    in_dir "$vuln" env SCAN_PATH=. CONFIG=p/default SEVERITY=INFO EXCLUDE_RULES= "$step" semgrep "Scan"
else
  echo "SKIP  scanner cases (set NEGATIVE_SCANNERS=1 to run them; self-check does)"
fi

# --- gitleaks: the organisation's own rules -------------------------------------------------------------------
# The org default config adds three rules that gitleaks' own rules lack: Azure Storage account keys, SAS and Power
# Automate signed URLs (sig=), and passwords in database or broker URLs, also with an empty user name. Every value
# is made up at run time and was never issued, and no line here matches a rule, so this repository's own scan
# stays clean. A case passes only when its own rule fires: the rule IDs come from a report of the same scan, made
# with the config the step wrote.
if [ "${NEGATIVE_SCANNERS:-0}" = 1 ] || [ -n "${LOCAL_GITLEAKS:-}" ]; then
  if [ -n "${LOCAL_GITLEAKS:-}" ]; then
    cp "$LOCAL_GITLEAKS" "$RUNNER_TEMP/gitleaks"
  elif [ ! -x "$RUNNER_TEMP/gitleaks" ]; then
    "$step" gitleaks "Install gitleaks"
  fi

  # planted <name> <printf format> <value>: a new repository whose one commit adds settings.txt, holding the
  # formatted line; prints its path.
  planted() {
    local d
    d="$(new_repo "$1")"
    # shellcheck disable=SC2059 # the format is the case's own fixture line
    printf "$2" "$3" > "$d/settings.txt"
    commit_all "$d"
    printf '%s\n' "$d"
  }

  # leak_rules <repo>: runs the gitleaks step on the repository with the org default config and exits with its
  # code, then prints the rule ID of each finding. Values stay redacted.
  leak_rules() {
    local rc=0
    (cd "$1" && CONFIG='' "$step" gitleaks "Scan the whole history") || rc=$?
    "$RUNNER_TEMP/gitleaks" git --no-banner --redact=100 --log-level error --config "$RUNNER_TEMP/gitleaks.toml" \
      --report-format json --report-path "$work/gitleaks-report.json" "$1" > /dev/null 2>&1 || true
    jq -r '.[].RuleID' "$work/gitleaks-report.json"
    return "$rc"
  }

  key="$(openssl rand -base64 64 | tr -d '\n')"
  sig="$(openssl rand -base64 33 | tr -d '\n' | tr '+/' '-_')"
  pass="$(openssl rand -hex 12)"

  repo="$(planted azure-key \
    'DefaultEndpointsProtocol=https;AccountName=notarealaccount;AccountKey=%s;EndpointSuffix=core.windows.net\n' "$key")"
  check "gitleaks: an Azure Storage account key fails on its own rule" nonzero '^azure-storage-account-key$' '' \
    leak_rules "$repo"
  repo="$(planted azure-sas 'https://notarealaccount.blob.core.windows.net/c/f.txt?sv=2022-11-02&sp=r&sig=%s\n' "$sig")"
  check "gitleaks: a signed URL (sig=) fails on its own rule" nonzero '^azure-sas-signature$' '' \
    leak_rules "$repo"
  repo="$(planted db-url 'DATABASE_URL=postgresql://app:%s@db.example.invalid:5432/app\n' "$pass")"
  check "gitleaks: a password in a database URL fails on its own rule" nonzero '^connection-string-password$' '' \
    leak_rules "$repo"
  repo="$(planted db-url-no-user 'REDIS_URL=redis://:%s@cache.example.invalid:6379/0\n' "$pass")"
  check "gitleaks: a password in a URL with an empty user name fails" nonzero '^connection-string-password$' '' \
    leak_rules "$repo"
  # One URL per argument, so this file never has two URLs in one string: the rule's password part would run on to
  # the later URL's @, and this repository's own scan would fail.
  repo="$(new_repo db-url-clean)"
  # shellcheck disable=SC2016 # the ${...} placeholders are fixture text, not expansions
  printf '%s\n' 'DATABASE_URL=postgresql://db.example.invalid:5432/app' 'REDIS_URL=redis://cache.example.invalid:6379/0' \
    'DATABASE_URL=postgresql://${PGUSER}:${PGPASSWORD}@db.example.invalid:5432/app' > "$repo/settings.txt"
  commit_all "$repo"
  check "gitleaks: database URLs with no password, or a placeholder, pass" 0 '' '' \
    leak_rules "$repo"
fi

if [ "${#failures[@]}" -gt 0 ]; then
  echo
  echo "${#failures[@]} case(s) did not behave as expected:"
  printf '  %s\n' "${failures[@]}"
  exit 1
fi
echo
echo "Every case behaved as expected."
