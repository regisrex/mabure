//
//  ReportWriter.swift
//  Mabure (menu bar agent)
//
//  Writes a human-readable incident report (Markdown) to disk every time a
//  notification is shown — a durable, easy-to-scan local record that
//  doesn't require grepping JSONL, and a fallback record if OS notification
//  permission is denied. Deliberately reuses exactly what DisplayEvent
//  already shows in the dropdown/notification — no new privacy exposure,
//  just a saved copy of the same information in a friendlier format.
//
//  Lives under the invoking user's own home directory (never the root-owned
//  /Library/... paths mabured writes to) so the unprivileged agent can
//  always write here with no install-time permission setup needed.
//

import Foundation

enum ReportWriter {
    static var reportsDir: URL {
        if let override = ProcessInfo.processInfo.environment["MABURE_REPORTS_DIR"] {
            return URL(fileURLWithPath: override)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Mabure/Reports")
    }

    private static let retentionDays = 90

    private static let filenameStamp: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd_HHmmss"
        return f
    }()

    private static let displayStamp: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .medium
        return f
    }()

    static func write(event: KillEvent, display: DisplayEvent) {
        let dir = reportsDir
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let stamp = filenameStamp.string(from: event.detectedDate ?? Date())
        let shortID = String(event.event_id.prefix(8))
        let kind = event.type == "git_block" ? "git-block" : "kill"
        let fileURL = dir.appendingPathComponent("\(stamp)_\(kind)_\(shortID).md")

        try? markdown(for: event, display: display).write(to: fileURL, atomically: true, encoding: .utf8)
        pruneOldReports(in: dir)
    }

    private static func markdown(for event: KillEvent, display: DisplayEvent) -> String {
        let when = event.detectedDate.map { displayStamp.string(from: $0) } ?? "unknown time"
        var lines = [
            "# \(display.title)",
            "",
            "- **When:** \(when)",
            "- **Type:** \(event.type == "git_block" ? "GitGuard revert" : "node -e kill")",
            "- **Event ID:** `\(event.event_id)`",
        ]
        if let detail = display.detail {
            lines.append("")
            lines.append("## Detail")
            lines.append("")
            for line in detail.split(separator: "\n") {
                lines.append("- \(line)")
            }
        } else {
            lines.append("")
            lines.append("_Belongs to another user on this Mac — details hidden per Mabure's cross-user privacy rule._")
        }
        lines.append("")
        lines.append("---")
        lines.append("_Full log: `/Library/Logs/Mabure/events.jsonl`_")
        return lines.joined(separator: "\n") + "\n"
    }

    /// Each report is tiny, but they accumulate forever otherwise — a
    /// light mtime-based sweep on every write keeps this bounded without
    /// needing a separate scheduled job.
    private static func pruneOldReports(in dir: URL) {
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: dir, includingPropertiesForKeys: [.contentModificationDateKey]
        ) else { return }
        let cutoff = Date().addingTimeInterval(-Double(retentionDays) * 86400)
        for file in files {
            guard let mtime = try? file.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate,
                  mtime < cutoff
            else { continue }
            try? FileManager.default.removeItem(at: file)
        }
    }
}
