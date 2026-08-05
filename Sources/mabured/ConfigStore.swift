//
//  ConfigStore.swift
//  mabured
//
//  Loads config.json (public, tuning-only) and allowlist.json (root-only,
//  never world-readable — see plan §0) and hot-reloads them by polling
//  mtime once per scan tick (cheap stat()).
//
//  All paths are overridable via environment variables so the daemon can be
//  run and fully verified (latency/soak/negative-case testing) as a normal
//  user, against the user's own processes, before it's ever installed as a
//  root LaunchDaemon. Production installs (Task 3) don't set these and get
//  the real system paths.
//

import Foundation

enum MaburePaths {
    static var configDir: String {
        ProcessInfo.processInfo.environment["MABURE_CONFIG_DIR"]
            ?? "/Library/Application Support/Mabure"
    }
    static var logDir: String {
        ProcessInfo.processInfo.environment["MABURE_LOG_DIR"]
            ?? "/Library/Logs/Mabure"
    }
    static var configPath: String { configDir + "/config.json" }
    static var allowlistPath: String { configDir + "/allowlist.json" }
    static var controlDir: String { configDir + "/control" }
    static var pauseSentinelPath: String { controlDir + "/paused" }
    static var fullLogPath: String { logDir + "/events.full.jsonl" }
    static var publicLogPath: String { logDir + "/events.jsonl" }
    static var gitBackupDir: String { logDir + "/git-guard-backups" }
}

struct Config: Codable {
    var schema: Int = 1
    var kill_enabled: Bool = true
    var dry_run: Bool = false
    var poll_interval_ms: Int = 100
    var heartbeat_interval_s: Int = 10
    var unreachable_after_missed_heartbeats: Int = 2
    var matched_flags: [String] = ["-e", "--eval", "--eval=", "-e="]
    var kill_children: Bool = true
    var concurrent_scan_threshold: Int = 8

    // GitGuard (see Sources/mabured/Git*.swift)
    var git_guard_enabled: Bool = true
    var git_revert_on_detect: Bool = true
    var git_scan_max_file_size_kb: Int = 2048
    /// A local, same-machine `git pull` can complete in as little as ~20-50ms
    /// (measured) — faster than the node-e path's 100ms cadence, and unlike
    /// node-e (which only needs to catch a process *appearing* once),
    /// GitGuard needs to observe both appear AND exit, doubling the chance a
    /// fast pull is invisible to a single poll rate. This runs the (cheap:
    /// a pid-set diff + basename check) appear/exit bookkeeping on its own
    /// much tighter timer, independent of the heavier per-pid node-e scan
    /// rate. Does not eliminate the race (an even faster operation could
    /// still slip through — inherent to any polling approach without
    /// EndpointSecurity), but shrinks the window substantially.
    var git_poll_interval_ms: Int = 20
}

struct Allowlist: Codable {
    var schema: Int = 1
    var parent_exec_paths: [String] = []
    var eval_prefixes: [String] = []
    var uids: [Int] = []

    /// Repo paths (exact or prefix match) GitGuard should never track at
    /// all — checked in GitProcessTracker.observeAppeared, so an exempted
    /// repo produces no log entry whatsoever, not just a skipped revert.
    var git_repo_paths: [String] = []
}

/// Tracks config/allowlist + their file mtimes, reloading only when a file
/// actually changed (avoids re-parsing JSON every 100ms tick for no reason).
final class ConfigStore {
    private(set) var config = Config()
    private(set) var allowlist = Allowlist()

    private var configMTime: Date?
    private var allowlistMTime: Date?

    init() {
        reloadIfChanged(force: true)
    }

    @discardableResult
    func reloadIfChanged(force: Bool = false) -> Bool {
        var changed = false

        let cMTime = Self.mtime(of: MaburePaths.configPath)
        if force || cMTime != configMTime {
            if let loaded: Config = Self.load(MaburePaths.configPath) {
                config = loaded
            }
            configMTime = cMTime
            changed = true
        }

        let aMTime = Self.mtime(of: MaburePaths.allowlistPath)
        if force || aMTime != allowlistMTime {
            if let loaded: Allowlist = Self.load(MaburePaths.allowlistPath) {
                allowlist = loaded
            }
            allowlistMTime = aMTime
            changed = true
        }

        return changed
    }

    private static func mtime(of path: String) -> Date? {
        (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
    }

    private static func load<T: Decodable>(_ path: String) -> T? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }
}

enum AllowlistChecker {
    /// Whether a matched pid should be exempted from killing.
    static func matches(pid: pid_t, argv: [String], meta: ProcessScanner.BSDInfo, allowlist: Allowlist) -> Bool {
        if allowlist.uids.contains(Int(meta.uid)) {
            return true
        }
        if !allowlist.parent_exec_paths.isEmpty,
           let parentPath = ProcessScanner.execPath(of: meta.ppid),
           allowlist.parent_exec_paths.contains(where: { parentPath.hasPrefix($0) }) {
            return true
        }
        if !allowlist.eval_prefixes.isEmpty, let evalBody = argv.last {
            if allowlist.eval_prefixes.contains(where: { evalBody.hasPrefix($0) }) {
                return true
            }
        }
        return false
    }

    /// Whether a repo path is exempted from GitGuard tracking entirely.
    static func gitRepoExempt(_ repoPath: String, allowlist: Allowlist) -> Bool {
        allowlist.git_repo_paths.contains { repoPath == $0 || repoPath.hasPrefix($0 + "/") }
    }
}
