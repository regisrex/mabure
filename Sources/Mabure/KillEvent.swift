//
//  KillEvent.swift
//  Mabure (menu bar agent)
//
//  Decodable model matching the public log schema written by mabured's
//  EventLogger (events.jsonl). Kept independent from the daemon target's
//  own Codable struct — the two targets are compiled/signed separately, and
//  this side only ever needs to decode, never encode.
//

import Foundation

/// Paths shared with the daemon's on-disk layout. Overridable via the same
/// env vars as the daemon (MABURE_LOG_DIR/MABURE_CONFIG_DIR) so the agent
/// can be pointed at a scratch directory for manual testing.
enum AgentPaths {
    static var configDir: String {
        ProcessInfo.processInfo.environment["MABURE_CONFIG_DIR"]
            ?? "/Library/Application Support/Mabure"
    }
    static var logDir: String {
        ProcessInfo.processInfo.environment["MABURE_LOG_DIR"]
            ?? "/Library/Logs/Mabure"
    }
    static var publicLogPath: String { logDir + "/events.jsonl" }
    static var controlDir: String { configDir + "/control" }
    static var pauseSentinelPath: String { controlDir + "/paused" }
}

struct KillEvent: Codable {
    var schema: Int?
    var event_id: String
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
    var reason: String?
    var message: String?

    // GitGuard fields
    var repo_path: String?
    var base_ref: String?
    var head_ref: String?
    var subcommand: String?
    var matched_rules: [String]?
    var reverted: Bool?
    var backup_patch_path: String?

    private static let iso: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    var detectedDate: Date? { Self.iso.date(from: detected_ts) }
}
