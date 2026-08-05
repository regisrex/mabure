//
//  IdentityFilter.swift
//  Mabure (menu bar agent)
//
//  Enforces the cross-user privacy rule (plan §3): the on-disk public log
//  still carries pid/uid/exec_path/argv for every user's events (root and
//  same-user tooling need that), but this UI layer shows full detail only
//  for events belonging to the viewing user. Everyone else's events show
//  only that *something* was killed, and when.
//
//  Applied uniformly to the dropdown row, the detail alert, and the
//  notification text — see DisplayEvent's use sites in StatusItemController
//  and AppDelegate.
//

import Darwin
import Foundation

struct DisplayEvent {
    let id: String
    let title: String
    let subtitle: String
    let isOwn: Bool
    /// Full detail text (argv, exec path, pid) — nil for other users' events.
    let detail: String?
}

enum IdentityFilter {
    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .none
        f.timeStyle = .medium
        return f
    }()

    static func present(_ event: KillEvent) -> DisplayEvent? {
        switch event.type {
        case "kill": return presentKill(event)
        case "git_block": return presentGitBlock(event)
        default: return nil
        }
    }

    private static func presentKill(_ event: KillEvent) -> DisplayEvent {
        let time = event.detectedDate.map { timeFormatter.string(from: $0) } ?? "unknown time"
        let latency = event.latency_ms.map { "\($0)ms" } ?? "?"
        let isOwn = event.uid.map { uid_t($0) == getuid() } ?? false

        if !isOwn {
            return DisplayEvent(
                id: event.event_id,
                title: "A process was killed on this Mac",
                subtitle: "\(time) · latency \(latency)",
                isOwn: false,
                detail: nil
            )
        }

        let cmd = (event.argv ?? []).joined(separator: " ")
        let truncatedCmd = cmd.count > 60 ? String(cmd.prefix(60)) + "…" : cmd
        return DisplayEvent(
            id: event.event_id,
            title: truncatedCmd.isEmpty ? "node -e (details unavailable)" : truncatedCmd,
            subtitle: "\(time) · pid \(event.pid.map(String.init) ?? "?") · latency \(latency)",
            isOwn: true,
            detail: "pid: \(event.pid.map(String.init) ?? "?")\n"
                + "exec: \(event.exec_path ?? "?")\n"
                + "argv: \(cmd)\n"
                + "user: \(event.username ?? "?")"
        )
    }

    /// GitGuard's presentation — repo name, matched rule names, subcommand,
    /// revert outcome, backup patch location. Never the raw matched code
    /// snippet inline, even for the owning user (matched_rules already
    /// carries only rule-name+path, not payload text) — same restraint
    /// principle as the kill path's cross-user redaction.
    private static func presentGitBlock(_ event: KillEvent) -> DisplayEvent {
        let time = event.detectedDate.map { timeFormatter.string(from: $0) } ?? "unknown time"
        let isOwn = event.uid.map { uid_t($0) == getuid() } ?? false
        let repoName = (event.repo_path as NSString?)?.lastPathComponent ?? "a repository"

        if !isOwn {
            return DisplayEvent(
                id: event.event_id,
                title: "A git pull was auto-reverted on this Mac",
                subtitle: time,
                isOwn: false,
                detail: nil
            )
        }

        let rules = (event.matched_rules ?? []).joined(separator: ", ")
        return DisplayEvent(
            id: event.event_id,
            title: "Blocked & reverted: \(repoName)",
            subtitle: "\(time) · \(event.subcommand ?? "pull")",
            isOwn: true,
            detail: "repo: \(event.repo_path ?? "?")\n"
                + "matched: \(rules.isEmpty ? "?" : rules)\n"
                + "reverted: \(event.reverted == true ? "yes" : "NO — see logs")\n"
                + "backup: \(event.backup_patch_path ?? "?")"
        )
    }
}
