# Mabure

A macOS menu-bar utility that detects and kills `node -e "..."` / `node --eval ...`
(inline eval) processes **system-wide**, within roughly 100ms of them starting, and
reports what it killed via a menu-bar dropdown, a notification, and an on-disk log.

## Why

`node -e` runs arbitrary code without ever writing a file to disk — a common way to run
one-off scripts, but also a known technique for running a payload stealthily. Mabure
watches for it across every user on the Mac and kills it near-instantly.

## Architecture

Killing *other users'* processes (and reading their argv) requires root; a GUI should
never run as root. So this is two components:

- **`mabured`** — a root **LaunchDaemon**, no UI. Polls the process table every 100ms,
  matches `node` processes whose argv contains `-e`/`--eval` (boundary-aware — it
  replicates Node's own CLI parsing, so `node script.js -e "..."` is correctly left
  alone), kills matches (and their children) with `SIGKILL`, and logs everything.
- **`Mabure.app`** — an unprivileged, per-user **LaunchAgent** menu-bar app
  (no Dock icon). Tails the daemon's log and renders the dropdown history + fires
  notifications. It never kills anything itself.

## GitGuard: malicious `git pull`/`merge` detection

`mabured` also watches for `git pull`/`git merge` system-wide. When one finishes, it scans
what just landed for malicious-code patterns informed by real 2025-2026 supply-chain
incidents (auto-run `postinstall`/`preinstall` scripts, obfuscated `eval(atob(...))`-style
payloads, pipe-to-shell, credential exfiltration, CI/hook file tampering — see
`Sources/mabured/MaliciousCodeHeuristics.swift` for the full rule list). If something
matches, it's auto-reverted (`git reset --hard`) within about a second, with a backup patch
saved to `/Library/Logs/Mabure/git-guard-backups/` before the revert so nothing is lost.

**Important limitation, stated plainly**: this is *detect-right-after-completion-and-revert*,
not true pre-landing prevention — git's `pre-merge-commit` hook (the only hook that can
truly abort a merge) doesn't run at all for fast-forward merges, the common case for a plain
`git pull`, so nothing can scan the diff before it exists. The malicious code does briefly
land on disk before being reverted; anything that could execute synchronously and instantly
during that window (rather than via a `postinstall` script, which runs later, when something
actually installs) is a real, accepted gap.

Runs as `pull`/`merge` only in v1 (`fetch` and `clone` are out of scope — see
`Sources/mabured/GitCommandMatcher.swift`'s header comment). Tune via the same
`config.json`/`allowlist.json` as the node-e guard — `git_guard_enabled`,
`git_revert_on_detect`, `git_scan_max_file_size_kb`, and an `allowlist.json` `git_repo_paths`
list to exempt specific repos entirely. `Tools/verify-gitguard-live.sh` runs a scratch-repo
end-to-end check (benign pull, malicious pull, postinstall-script pull) against the real
installed daemon.

### Campaign-specific markers (PolinRider / TasksJacker)

`Sources/mabured/PolinRiderMarkers.swift` adds a small set of near-zero-false-positive,
literal indicators for the active DPRK PolinRider/TasksJacker supply-chain campaign
(108+ malicious packages across npm/Packagist/Go/Chrome Web Store as of mid-2026 —
[Socket.dev](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands),
[OpenSourceMalware](https://opensourcemalware.com/blog/tasksjacker-blog-post)): specific
packed-string fragments, `global['!']=`/`global['_V']=` injection keys, and a couple of
leaked build-environment artifacts. These are point-in-time IOCs, not structural
properties — expect this file to need periodic updates as the campaign evolves, unlike
`MaliciousCodeHeuristics.swift`'s behavioral rules.

`Sources/mabured/BinaryMasqueradeScanner.swift` closes a real gap the general content
rules can't reach: PolinRider hides JS loaders inside files with binary-looking extensions
(`.woff2`, `.wasm`, `.png`, ...), and git's own diff shows zero content for a true binary
file. For files git flags as binary *and* whose extension is masquerade-prone, this fetches
the actual blob and checks for loader-shaped text (`require(`, `child_process`, `atob(`, ...)
where a real font/wasm/image's binary header should be — finding any of it at all is the
signal, regardless of what else is in the file.

`Sources/mabured/VSCodeTaskMarkers.swift` targets the **TasksJacker** vector (an evolution of
the same DPRK cluster — [OpenSourceMalware](https://opensourcemalware.com/blog/tasksjacker-blog-post),
[VS Code issue #309406](https://github.com/microsoft/vscode/issues/309406)): a
`.vscode/tasks.json` entry with `"runOn": "folderOpen"` executes the instant a workspace is
opened in VS Code, silently, before any code review. Path-gated to `.vscode/tasks.json`,
`.vscode/settings.json`, and `*.code-workspace` — checks for `runOn: folderOpen`, a pull
re-enabling `task.allowAutomaticTasks` (the exact setting Microsoft shipped to stop this),
`node` pointed at a font/wasm-shaped path (the TasksJacker+fake-font combo), and known C2
domains for this campaign (kept corroborating-only, since e.g. `vercel.app` alone is far too
common to auto-revert on by itself).

No Apple EndpointSecurity framework is used (it requires a special entitlement Apple
only grants to enrolled paid developer accounts). Detection is a tight poll loop
instead — in practice 15–90ms from process start to kill, well under the ~1s target.

## Install

```sh
sudo ./install.sh
```

This builds both binaries, ad-hoc code-signs them, creates a `_mabure` group (for
passwordless pause access), installs the daemon + agent + configs, and loads both via
`launchctl`. Safe to re-run (idempotent).

**After installing:** log out and back in once. macOS caches group membership in your
login session's credential, so the Pause/Resume menu item won't work until you do —
this is expected on first install, not a bug. The daemon and agent themselves start
working immediately, no relogin needed for detection/killing.

You'll also see a one-time notification-permission prompt from Mabure the first time
the agent runs — allow it if you want the notification banners; the dropdown and log
work regardless.

## Uninstall

```sh
sudo ./uninstall.sh          # keeps log files
sudo ./uninstall.sh --purge-logs   # also deletes them
```

## Configuration

Edit `/Library/Application Support/Mabure/config.json` (world-readable, no sudo needed
to read, sudo needed to edit):

```json
{
  "kill_enabled": true,
  "dry_run": false,
  "poll_interval_ms": 100,
  "matched_flags": ["-e", "--eval", "--eval=", "-e="],
  "kill_children": true
}
```

Set `"dry_run": true` to trial it first (logs what *would* be killed, without killing) —
recommended on any machine with active dev tooling before relying on this fleet-wide,
since `node -e` is an extremely common, benign idiom (Homebrew/nvm/postinstall probes).

`/Library/Application Support/Mabure/allowlist.json` (root-only, 0600 — never
world-readable, since a world-readable allowlist would hand every local user the exact
criteria to evade detection):

```json
{
  "parent_exec_paths": [],
  "eval_prefixes": [],
  "uids": []
}
```

Both files are hot-reloaded (checked once per poll tick) — no restart needed.

## Pausing

- **Soft pause** (from the menu, no sudo): click "Pause" in the dropdown. Requires
  `_mabure` group membership + a fresh login (see Install, above).
- **Hard pause** (fully stops the daemon):
  ```sh
  sudo launchctl bootout system/com.mabure.daemon
  # ...later:
  sudo launchctl bootstrap system /Library/LaunchDaemons/com.mabure.daemon.plist
  ```
  On resume, the daemon re-scans every already-running `node` process before settling
  into steady state, so anything that started evaling during the pause is still caught.

Trade-off, stated plainly: any `_mabure` group member can disable detection with no
password prompt. That's a deliberate convenience/security trade-off for a personal Mac.

## Logs

- `/Library/Logs/Mabure/events.jsonl` — world-readable, one JSON object per line. The
  eval body is replaced with a SHA-256 fingerprint here (so no local user can read
  another user's payload off disk); this is also the only channel the menu-bar agent
  reads from.
- `/Library/Logs/Mabure/events.full.jsonl` — root-only (0600), same events with the
  real eval body included.

The agent's dropdown/notifications additionally hide pid/uid/exec_path/argv for events
that don't belong to the viewing user — even though the log file itself still contains
that data for every user (root/same-user tooling needs it). A sufficiently motivated
local user could still read the raw file directly; this is a documented, accepted gap
(see Risks).

**Per-user incident reports**: every time a notification fires (kill or GitGuard revert),
a matching human-readable Markdown report is also saved to
`~/Library/Application Support/Mabure/Reports/` — reuses exactly what the notification/
dropdown already shows (no new privacy exposure), written even if OS notification
permission is denied, and auto-pruned after 90 days.

Every notification also has a **Report Bug** action button (long-press/click "Options" on
the banner, or from Notification Center) that opens a pre-filled GitHub issue on
[regisrex/mabure](https://github.com/regisrex/mabure/issues) — deliberately generic
(event type/time/id only; this repo is public, so no file paths, commands, or matched
content are ever auto-included).

## Verifying it works

```sh
node -e "setTimeout(()=>{},5000)"   # should die almost immediately
tail -f "/Library/Logs/Mabure/events.jsonl"
```

Things that must **survive** (not get killed):
- `node server.js` / any script file
- a bare `node` REPL
- `node --version`
- `node script.js -e "..."` — the script's own argument, not node's flag
- `node -- -e "text"` — the `--` terminator makes `-e` a literal filename argument

## Known risks / accepted limitations

- **`KERN_PROCARGS2`** (how argv is read) is an undocumented-but-decades-stable Darwin
  sysctl — every process tool (`ps`, `top`, Activity Monitor) relies on it, but it's not
  an Apple-guaranteed contract.
- **Sub-poll-interval processes** (start and fully exit within ~100ms) are structurally
  invisible without Apple's EndpointSecurity framework, which isn't available here.
- **`node -e -- "payload"`** gets killed even though Node treats the literal `"--"` as
  the eval body and `"payload"` never actually runs — the matcher fires on argv
  *shape* (`-e` followed by something), not on what code Node will execute. A known,
  accepted false-positive class, not worth a full Node-argument-value emulator to close.
- **Any local admin** can disable this with no sudo prompt via System Settings > Login
  Items, or via `_mabure` group pause access. Expected/benign for a personal Mac; a
  managed fleet would need an MDM-deployed Login Items profile (out of scope here).
- This is a **root daemon that SIGKILLs matching processes system-wide**, driven by
  argv it doesn't control. Kept deliberately minimal — `mabured` only
  enumerates/matches/kills/logs; all formatting/redaction happens in the unprivileged
  agent.

## Repo layout

```
Sources/mabured/   root daemon (process scanning, matching, killing, logging)
Sources/Mabure/    menu-bar agent (status item, log tailing, notifications)
Resources/         Info.plist template, launchd plists, newsyslog config
Config/            default config.json / allowlist.json
build.sh           builds both targets as universal2 binaries via swiftc
install.sh / uninstall.sh
```
