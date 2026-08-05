//
//  GitProcessTracker.swift
//  mabured
//
//  Tracks git pull/merge invocations from process-start to process-exit.
//  Git processes are never our children, so we can't waitpid() them — we
//  detect completion the same way Watcher detects new pids: by diffing
//  listAllPids() against a remembered set, but for *disappearance* instead
//  of appearance.
//

import Foundation

struct TrackedGitOp {
    let pid: pid_t
    let repoPath: String        // resolved: -C override, else libproc cwd
    let subcommand: String      // "pull" | "merge"
    let uid: uid_t
    let startTimeSec: Int64
    let startTimeUsec: Int64
    /// HEAD SHA captured the instant we started tracking — an independent
    /// "before" fallback if ORIG_HEAD is absent/stale after the op (e.g. a
    /// second overlapping pull in the same repo — see plan risks).
    let preOpHeadSHA: String?
}

enum GitPathResolver {
    /// -C argv override takes precedence; else the process's own cwd via
    /// libproc PROC_PIDVNODEPATHINFO.
    static func resolveRepoPath(pid: pid_t, dashCOverride: String?) -> String? {
        let cwd = ProcessScanner.cwd(of: pid)
        if let override = dashCOverride {
            if override.hasPrefix("/") { return canonicalize(override) }
            guard let base = cwd else { return nil }
            return canonicalize((base as NSString).appendingPathComponent(override))
        }
        guard let cwd else { return nil }
        return canonicalize(cwd)
    }

    private static func canonicalize(_ path: String) -> String {
        (path as NSString).standardizingPath
    }
}

final class GitProcessTracker {
    private var tracked: [pid_t: TrackedGitOp] = [:]
    /// Repo paths with a scan/revert currently in flight — guards against
    /// two concurrent pulls in the SAME repo racing each other's revert.
    /// `main.swift` dispatches GitRevertEngine.handle onto a *concurrent*
    /// gitQueue (different repos should scan in parallel), so multiple
    /// threads can call markInFlight/clearInFlight simultaneously — this
    /// needs its own lock, unlike `tracked` above (which is only ever
    /// touched serially from tick()'s scanQueue).
    private var reposInFlight: Set<String> = []
    private let reposInFlightLock = NSLock()

    /// Call once per tick, on the same queue as the rest of tick(), with
    /// newly-appeared pids. Registers any new git pull/merge invocations.
    func observeAppeared(
        pids: [pid_t], config: Config, allowlist: Allowlist,
        argMax: Int32, scratch: UnsafeMutableRawPointer
    ) {
        for pid in pids {
            guard tracked[pid] == nil,
                  ProcessScanner.execBasename(of: pid) == "git",
                  let argv = ArgvParser.fetch(pid: pid, argMax: argMax, scratch: scratch)
            else { continue }

            let match = GitCommandMatcher.classify(argv: argv)
            guard let sub = match.subcommand, sub == "pull" || sub == "merge" else { continue }
            guard let meta = ProcessScanner.bsdInfo(of: pid) else { continue }

            guard let repoPath = GitPathResolver.resolveRepoPath(pid: pid, dashCOverride: match.dashCPath) else {
                continue
            }

            if AllowlistChecker.gitRepoExempt(repoPath, allowlist: allowlist) {
                continue
            }

            let preHead = GitShell.revParse(ref: "HEAD", repoPath: repoPath, uid: meta.uid)
            tracked[pid] = TrackedGitOp(
                pid: pid, repoPath: repoPath, subcommand: sub, uid: meta.uid,
                startTimeSec: meta.startTimeSec, startTimeUsec: meta.startTimeUsec,
                preOpHeadSHA: preHead
            )
        }
    }

    /// Call once per tick with the current pid set. Returns tracked ops
    /// whose pid has disappeared (the git process finished), removing them
    /// from the map.
    func drainExited(currentPids: Set<pid_t>) -> [TrackedGitOp] {
        let exitedPids = tracked.keys.filter { !currentPids.contains($0) }
        var result: [TrackedGitOp] = []
        for pid in exitedPids {
            if let op = tracked.removeValue(forKey: pid) { result.append(op) }
        }
        return result
    }

    /// Returns false if a scan/revert is already running for this repo —
    /// caller should skip (and log) rather than run a second one in parallel.
    func markInFlight(_ repoPath: String) -> Bool {
        reposInFlightLock.lock()
        defer { reposInFlightLock.unlock() }
        if reposInFlight.contains(repoPath) { return false }
        reposInFlight.insert(repoPath)
        return true
    }

    func clearInFlight(_ repoPath: String) {
        reposInFlightLock.lock()
        defer { reposInFlightLock.unlock() }
        reposInFlight.remove(repoPath)
    }
}
