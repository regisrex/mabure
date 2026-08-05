//
//  main.swift
//  mabured
//
//  Entry point for the root LaunchDaemon. Plain top-level executable code
//  (not -parse-as-library) — see plan §6.
//
//  CLI flags, useful for manual verification without a full root install:
//    --once       run a single scan tick (startup live-scan included) and
//                 exit, instead of polling forever.
//    --dry-run    force config.dry_run = true regardless of config.json —
//                 log what *would* be killed without actually killing it.
//
//  All state paths (config/allowlist/logs/control dir) are overridable via
//  MABURE_CONFIG_DIR / MABURE_LOG_DIR env vars (see ConfigStore.swift), so
//  this same binary can be run unprivileged against one's own processes for
//  end-to-end testing before it's ever installed as a root daemon.
//

import Darwin
import Foundation

// Long-running process whose stdout/stderr are redirected to log files by
// launchd (and, for manual testing, by the shell) — never a tty. Without
// this, output sits in a stdio buffer instead of reaching the log promptly.
setvbuf(stdout, nil, _IONBF, 0)
setvbuf(stderr, nil, _IONBF, 0)

let cliArgs = CommandLine.arguments
let runOnce = cliArgs.contains("--once")
let forceDryRun = cliArgs.contains("--dry-run")

final class Watcher {
    private let store = ConfigStore()
    private let heartbeat = Heartbeat()
    private var knownPids: Set<pid_t> = []
    private let argMax: Int32
    private let scratch: UnsafeMutableRawPointer
    private var timer: DispatchSourceTimer?
    private let scanQueue = DispatchQueue(label: "com.mabure.daemon.scan")

    // GitGuard: appear/exit bookkeeping runs on its own, much tighter timer
    // (see Config.git_poll_interval_ms) than the node-e path — a fast local
    // git pull can complete in ~20-50ms, faster than the 100ms node-e
    // cadence, and GitGuard needs to observe both appearance AND exit
    // (node-e only needs appearance), doubling the miss risk at a shared
    // rate. Both timers target scanQueue (serially) so GitProcessTracker's
    // `tracked` dict is never touched from two threads at once. The actual
    // scan/revert work is dispatched onto this separate *concurrent* queue
    // so a slow su+git subprocess or a large diff never delays either timer.
    private let gitTracker = GitProcessTracker()
    private let gitQueue = DispatchQueue(label: "com.mabure.daemon.gitguard", attributes: .concurrent)
    private var gitTimer: DispatchSourceTimer?
    private var knownPidsForGit: Set<pid_t> = []
    private var lastGitPollIntervalMs = -1

    init() {
        argMax = ArgvParser.queryArgMax()
        guard let buf = malloc(Int(argMax)) else {
            EventLogger.logError("mabured: failed to allocate \(argMax)-byte argv scratch buffer")
            exit(1)
        }
        scratch = buf
    }

    private var effectiveConfig: Config {
        var c = store.config
        if forceDryRun { c.dry_run = true }
        return c
    }

    /// Runs the matcher against every already-running node process once,
    /// before switching to steady-state new-pid diffing. Without this, a
    /// daemon crash/restart (or resume from a hard pause) creates a silent,
    /// permanent detection hole for whatever eval was mid-flight at that
    /// exact instant — this closes that gap.
    func startupLiveScan(pids: [pid_t]) {
        let config = effectiveConfig
        let allowlist = store.allowlist
        for pid in pids where ProcessScanner.execBasename(of: pid) == "node" {
            KillEngine.handle(newPid: pid, config: config, allowlist: allowlist, argMax: argMax, scratch: scratch)
        }
    }

    func start() {
        let initial = ProcessScanner.listAllPids()
        startupLiveScan(pids: initial)
        knownPids = Set(initial)
        knownPidsForGit = Set(initial)

        scheduleTimer(intervalMs: effectiveConfig.poll_interval_ms)
        if effectiveConfig.git_guard_enabled {
            scheduleGitTimer(intervalMs: effectiveConfig.git_poll_interval_ms)
        }
        dispatchMain()
    }

    func runSingleTick() {
        let initial = ProcessScanner.listAllPids()
        startupLiveScan(pids: initial)
    }

    private func scheduleTimer(intervalMs: Int) {
        let t = DispatchSource.makeTimerSource(queue: scanQueue)
        t.schedule(
            deadline: .now() + .milliseconds(intervalMs),
            repeating: .milliseconds(intervalMs),
            leeway: .milliseconds(5)
        )
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    private func scheduleGitTimer(intervalMs: Int) {
        let t = DispatchSource.makeTimerSource(queue: scanQueue)
        t.schedule(
            deadline: .now() + .milliseconds(intervalMs),
            repeating: .milliseconds(intervalMs),
            leeway: .milliseconds(2)
        )
        t.setEventHandler { [weak self] in self?.gitTick() }
        t.resume()
        gitTimer = t
    }

    private var lastPollIntervalMs = -1

    private func tick() {
        let changed = store.reloadIfChanged()
        let config = effectiveConfig
        let allowlist = store.allowlist

        if changed && config.poll_interval_ms != lastPollIntervalMs {
            lastPollIntervalMs = config.poll_interval_ms
            scheduleTimer(intervalMs: config.poll_interval_ms)
        }

        // GitGuard timer: start/stop/reschedule in reaction to config
        // changes (enabled toggle, or a tuned git_poll_interval_ms).
        if changed {
            if config.git_guard_enabled, gitTimer == nil {
                knownPidsForGit = Set(ProcessScanner.listAllPids())  // fresh baseline, avoid a backlog
                scheduleGitTimer(intervalMs: config.git_poll_interval_ms)
                lastGitPollIntervalMs = config.git_poll_interval_ms
            } else if !config.git_guard_enabled, let t = gitTimer {
                t.cancel()
                gitTimer = nil
            } else if config.git_guard_enabled, config.git_poll_interval_ms != lastGitPollIntervalMs {
                lastGitPollIntervalMs = config.git_poll_interval_ms
                scheduleGitTimer(intervalMs: config.git_poll_interval_ms)
            }
        }

        heartbeat.emitIfDue(intervalSeconds: config.heartbeat_interval_s)

        let paused = PauseController.isPaused()
        let current = Set(ProcessScanner.listAllPids())
        defer { knownPids = current }

        if paused {
            EventLogger.logStateTransitionOnce(state: "paused")
            return
        }
        EventLogger.logStateTransitionOnce(state: "watching")

        let newPids = Array(current.subtracting(knownPids))
        guard !newPids.isEmpty else { return }

        // A burst of concurrently-spawned processes (build system, fork
        // storm) must not serialize this tick's per-pid work past the poll
        // interval — fan out above a small threshold; serial below it
        // (simpler, no contention, and the common case).
        if newPids.count > config.concurrent_scan_threshold {
            DispatchQueue.concurrentPerform(iterations: newPids.count) { idx in
                KillEngine.handle(newPid: newPids[idx], config: config, allowlist: allowlist, argMax: argMax, scratch: scratch)
            }
        } else {
            for pid in newPids {
                KillEngine.handle(newPid: pid, config: config, allowlist: allowlist, argMax: argMax, scratch: scratch)
            }
        }
    }

    /// GitGuard's own tighter-cadence tick (see Config.git_poll_interval_ms):
    /// just the cheap appear/exit bookkeeping — mirrors tick()'s new/known
    /// pid diffing exactly, but on its own timer so a fast local git pull
    /// isn't invisible to the heavier node-e cadence. Runs on scanQueue
    /// (same thread as tick()), so GitProcessTracker's `tracked` dict is
    /// never touched concurrently by both timers.
    private func gitTick() {
        let config = effectiveConfig
        let allowlist = store.allowlist

        // Pause applies here too — Pause means "stop watching," full stop.
        // Still update the baseline every tick (even while paused) so
        // resuming doesn't suddenly treat every process that started during
        // the pause as "new" (mirrors tick()'s own defer-based update).
        let current = Set(ProcessScanner.listAllPids())
        defer { knownPidsForGit = current }
        guard !PauseController.isPaused() else { return }

        let newPids = Array(current.subtracting(knownPidsForGit))
        gitTracker.observeAppeared(pids: newPids, config: config, allowlist: allowlist, argMax: argMax, scratch: scratch)

        let exitedGitOps = gitTracker.drainExited(currentPids: current)
        for op in exitedGitOps {
            gitQueue.async { [gitTracker] in
                GitRevertEngine.handle(op: op, config: config, tracker: gitTracker)
            }
        }
    }
}

EventLogger.openFiles()
let watcher = Watcher()

if runOnce {
    watcher.runSingleTick()
    exit(0)
} else {
    watcher.start()
}
