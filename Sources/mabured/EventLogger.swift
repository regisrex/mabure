//
//  EventLogger.swift
//  mabured
//
//  Append-only JSON-lines event log, split into two files (see plan §3):
//    - events.full.jsonl (0600, root-only) — carries the real eval body.
//    - events.jsonl       (0644, world-readable) — the sole IPC channel to
//      every user's menu-bar agent; the eval body is replaced with a
//      SHA-256+length fingerprint so no local user can read another user's
//      payload off disk.
//
//  Property names intentionally match the on-disk JSON schema in the plan
//  (snake_case) rather than Swift convention, so the struct doubles as
//  documentation of the wire format.
//

import Foundation
import CryptoKit

struct KillEvent: Codable {
    var schema: Int = 1
    var event_id: String
    // kill | kill_child | ambiguous_no_kill | pid_reused_abort | allowlist_skip |
    // state_change | heartbeat | error |
    // git_block | git_scan_clean | git_scan_ambiguous | git_revert_failed | git_skipped_concurrent
    var type: String
    var detected_ts: String
    var start_ts: String?
    var kill_ts: String?
    var latency_ms: Int64?
    var detect_latency_ms: Int64?
    var pid: Int32?
    var ppid: Int32?
    var uid: Int32?
    var username: String?
    var exec_path: String?
    var argv: [String]?
    var matched_token: String?
    var kill_signal: String?
    var kill_result: String?
    var kill_errno: Int32?
    var children_killed: [Int32]?
    var allowlisted: Bool?
    var dry_run: Bool?
    var parent_event_id: String?
    var reason: String?
    var message: String?

    // GitGuard fields
    var repo_path: String?
    var base_ref: String?
    var head_ref: String?
    var subcommand: String?           // "pull" | "merge"
    var matched_rules: [String]?
    var reverted: Bool?
    var backup_patch_path: String?
}

enum EventLogger {
    private static let iso: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    static func nowString(_ date: Date = Date()) -> String { iso.string(from: date) }

    static func startTimeString(sec: Int64, usec: Int64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(sec) + TimeInterval(usec) / 1_000_000)
        return iso.string(from: date)
    }

    // MARK: - File handles (opened once, reused; append-only)

    private static var fullFD: Int32 = -1
    private static var publicFD: Int32 = -1
    private static var lastLoggedState: String?

    static func openFiles() {
        fullFD = openAppend(path: MaburePaths.fullLogPath, mode: 0o600)
        publicFD = openAppend(path: MaburePaths.publicLogPath, mode: 0o644)
    }

    private static func openAppend(path: String, mode: mode_t) -> Int32 {
        try? FileManager.default.createDirectory(
            atPath: (path as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true
        )
        let fd = open(path, O_WRONLY | O_CREAT | O_APPEND, mode)
        if fd >= 0 {
            fchmod(fd, mode)  // enforce mode even if umask weakened it at creation
        } else {
            FileHandle.standardError.write("mabured: failed to open \(path): errno=\(errno)\n".data(using: .utf8)!)
        }
        return fd
    }

    private static func writeLine(_ fd: Int32, _ event: KillEvent) {
        guard fd >= 0 else { return }
        guard var data = try? JSONEncoder().encode(event) else { return }
        data.append(0x0A)  // newline
        data.withUnsafeBytes { buf in
            _ = write(fd, buf.baseAddress, buf.count)
        }
    }

    /// Redacts the last argv element (the eval body) to a hash+length, for
    /// the world-readable public log.
    private static func redactedArgv(_ argv: [String]) -> [String] {
        guard var last = argv.last else { return argv }
        var out = argv
        let digest = SHA256.hash(data: Data(last.utf8)).map { String(format: "%02x", $0) }.joined()
        last = "‹redacted \(last.count) chars sha256:\(String(digest.prefix(16)))…›"
        out[out.count - 1] = last
        return out
    }

    // MARK: - Public logging entry points

    static func logMatch(
        eventID: String, pid: pid_t, argv: [String], meta: ProcessScanner.BSDInfo,
        matchedToken: String, killed: Bool, killErrno: Int32? = nil,
        detectedTS: Date = Date(), killTS: Date? = nil,
        children: [pid_t] = [], allowlisted: Bool = false, dryRun: Bool = false, reason: String? = nil
    ) {
        let startTS = startTimeString(sec: meta.startTimeSec, usec: meta.startTimeUsec)
        let startInterval = TimeInterval(meta.startTimeSec) + TimeInterval(meta.startTimeUsec) / 1_000_000
        let detectLatency = Int64((detectedTS.timeIntervalSince1970 - startInterval) * 1000)
        let killLatency = killTS.map { Int64(($0.timeIntervalSince1970 - startInterval) * 1000) }

        var full = KillEvent(
            event_id: eventID, type: "kill", detected_ts: nowString(detectedTS),
            start_ts: startTS, kill_ts: killTS.map { nowString($0) },
            latency_ms: killLatency, detect_latency_ms: detectLatency,
            pid: pid, ppid: meta.ppid, uid: Int32(meta.uid), username: ProcessScanner.username(forUID: meta.uid),
            exec_path: ProcessScanner.execPath(of: pid), argv: argv, matched_token: matchedToken,
            kill_signal: killed ? "SIGKILL" : nil, kill_result: killed ? "success" : (reason ?? "not_attempted"),
            kill_errno: killErrno, children_killed: children.map { Int32($0) },
            allowlisted: allowlisted, dry_run: dryRun
        )
        writeLine(fullFD, full)

        full.argv = argv.isEmpty ? argv : redactedArgv(argv)
        writeLine(publicFD, full)
    }

    static func logChildKill(parentEventID: String, pid: pid_t, meta: ProcessScanner.BSDInfo, killed: Bool) {
        let event = KillEvent(
            event_id: UUID().uuidString, type: "kill_child", detected_ts: nowString(),
            pid: pid, ppid: meta.ppid, uid: Int32(meta.uid), username: ProcessScanner.username(forUID: meta.uid),
            exec_path: ProcessScanner.execPath(of: pid),
            kill_signal: killed ? "SIGKILL" : nil, kill_result: killed ? "success" : "failed",
            parent_event_id: parentEventID
        )
        writeLine(fullFD, event)
        writeLine(publicFD, event)
    }

    static func logAmbiguous(pid: pid_t, argv: [String], naiveToken: String) {
        var event = KillEvent(
            event_id: UUID().uuidString, type: "ambiguous_no_kill", detected_ts: nowString(),
            pid: pid, argv: argv, matched_token: naiveToken
        )
        writeLine(fullFD, event)
        event.argv = nil  // full argv is the sensitive/diagnostic bit here; public log doesn't need it
        writeLine(publicFD, event)
    }

    static func logPidReusedAbort(eventID: String, pid: pid_t, argv: [String]) {
        let event = KillEvent(
            event_id: eventID, type: "pid_reused_abort", detected_ts: nowString(),
            pid: pid, argv: argv, reason: "start_time_mismatch_before_kill"
        )
        writeLine(fullFD, event)
        // Not written to the public log — no kill occurred, nothing actionable for a user's agent.
    }

    static func logAllowlistSkip(pid: pid_t, argv: [String], reason: String) {
        var event = KillEvent(
            event_id: UUID().uuidString, type: "allowlist_skip", detected_ts: nowString(),
            pid: pid, argv: argv, reason: reason
        )
        writeLine(fullFD, event)
        event.argv = redactedArgv(argv)
        writeLine(publicFD, event)
    }

    /// Logs a state transition exactly once (not every tick) — call every
    /// tick with the current state string; it's a no-op unless it changed.
    static func logStateTransitionOnce(state: String) {
        guard state != lastLoggedState else { return }
        lastLoggedState = state
        let event = KillEvent(event_id: UUID().uuidString, type: "state_change", detected_ts: nowString(), reason: state)
        writeLine(fullFD, event)
        writeLine(publicFD, event)
    }

    static func logHeartbeat() {
        let event = KillEvent(event_id: UUID().uuidString, type: "heartbeat", detected_ts: nowString())
        writeLine(publicFD, event)  // heartbeat is UI-facing only; not worth the full log's noise
    }

    static func logError(_ message: String) {
        let event = KillEvent(event_id: UUID().uuidString, type: "error", detected_ts: nowString(), message: message)
        writeLine(fullFD, event)
        FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    }

    // MARK: - GitGuard logging

    /// The rare, actionable case — malicious content was found and
    /// (attempted to be) reverted. Both logs: this is exactly the kind of
    /// event the dropdown/notification exist for.
    static func logGitBlock(
        eventID: String, op: TrackedGitOp, baseSHA: String, headSHA: String,
        matchedRules: [String], reverted: Bool, backupPatchPath: String
    ) {
        let event = KillEvent(
            event_id: eventID, type: "git_block", detected_ts: nowString(),
            pid: op.pid, uid: Int32(op.uid), username: ProcessScanner.username(forUID: op.uid),
            repo_path: op.repoPath, base_ref: baseSHA, head_ref: headSHA, subcommand: op.subcommand,
            matched_rules: matchedRules, reverted: reverted, backup_patch_path: backupPatchPath
        )
        writeLine(fullFD, event)
        writeLine(publicFD, event)
    }

    /// Every ordinary git pull, all day — full-log only, same tiering as
    /// ambiguous_no_kill/heartbeat, so the dropdown/notifications aren't
    /// spammed by the overwhelmingly common non-malicious case.
    static func logGitScanClean(eventID: String, op: TrackedGitOp, base: String, head: String) {
        let event = KillEvent(
            event_id: eventID, type: "git_scan_clean", detected_ts: nowString(),
            pid: op.pid, repo_path: op.repoPath, base_ref: base, head_ref: head, subcommand: op.subcommand
        )
        writeLine(fullFD, event)
    }

    /// Weak (severity-2-only, uncorroborated) signal — observed, not acted
    /// on. Full-log only.
    static func logGitScanAmbiguous(eventID: String, op: TrackedGitOp, base: String, head: String, matchedRules: [String]) {
        let event = KillEvent(
            event_id: eventID, type: "git_scan_ambiguous", detected_ts: nowString(),
            pid: op.pid, repo_path: op.repoPath, base_ref: base, head_ref: head, subcommand: op.subcommand,
            matched_rules: matchedRules
        )
        writeLine(fullFD, event)
    }

    /// Something bad was found AND the revert itself didn't work (or a
    /// rev-parse/diff step failed) — rare and urgent, both logs.
    static func logGitRevertFailed(eventID: String, op: TrackedGitOp, stage: String) {
        let event = KillEvent(
            event_id: eventID, type: "git_revert_failed", detected_ts: nowString(),
            pid: op.pid, reason: stage, repo_path: op.repoPath, subcommand: op.subcommand
        )
        writeLine(fullFD, event)
        writeLine(publicFD, event)
    }

    static func logGitSkippedConcurrent(repoPath: String) {
        let event = KillEvent(
            event_id: UUID().uuidString, type: "git_skipped_concurrent", detected_ts: nowString(),
            repo_path: repoPath
        )
        writeLine(fullFD, event)
    }
}
