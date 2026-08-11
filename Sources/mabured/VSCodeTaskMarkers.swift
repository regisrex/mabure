//
//  VSCodeTaskMarkers.swift
//  mabured
//
//  Path-aware rules for VS Code's task-auto-run vector — the mechanism
//  behind the TasksJacker campaign (an evolution of the DPRK PolinRider/
//  Contagious Interview cluster, see PolinRiderMarkers.swift): a
//  `.vscode/tasks.json` entry with "runOn": "folderOpen" (nested under
//  "runOptions") executes the instant a workspace is opened in VS Code —
//  in a trusted workspace, silently, before any code review or extension
//  load. Microsoft's VS Code 1.109 (Jan 2026) added `task.allowAutomaticTasks`
//  (default "off") as a mitigation, but a malicious pull re-enabling it in
//  a repo's own committed .vscode/settings.json defeats that default for
//  anyone who opens the workspace afterward.
//
//  Sources:
//    - https://opensourcemalware.com/blog/tasksjacker-blog-post
//    - https://github.com/microsoft/vscode/issues/309406
//    - https://opensourcemalware.com/blog/mini-shai-hulud-weaponizes-tasks-json-files
//
//  Path-gated (only evaluated for .vscode/tasks.json, .vscode/settings.json,
//  and *.code-workspace — which can embed both "tasks" and "settings"
//  sections) rather than scanned anywhere: these are VS Code-specific
//  config keys that only actually do anything from within these files, so
//  gating tightly here cuts false positives with zero coverage loss.
//

import Foundation

enum VSCodeTaskMarkers {
    private static let relevantPathSuffixes = [
        ".vscode/tasks.json", ".vscode/settings.json", ".code-workspace",
    ]

    static func evaluate(_ file: GitDiffFile) -> [MatchedRule] {
        guard relevantPathSuffixes.contains(where: { file.pathB.hasSuffix($0) }) else { return [] }
        let text = file.addedLinesText
        guard !text.isEmpty else { return [] }
        var out: [MatchedRule] = []

        func hit(_ name: String, _ pattern: String, severity: Int, options: NSRegularExpression.Options = []) {
            if let rule = RegexRuleMatcher.firstMatch(name, pattern, in: text, filePath: file.pathB, severity: severity, options: options) {
                out.append(rule)
            }
        }

        // The core TasksJacker mechanism: a task set to auto-run the
        // instant the workspace is opened, before any human review.
        hit("vscode_task_autorun_on_folder_open", #""runOn"\s*:\s*"folderOpen""#, severity: 3)

        // Re-enabling the exact setting Microsoft shipped specifically to
        // stop this — seeing it flipped on via an incoming pull (rather
        // than a developer's own local choice) is itself a strong signal.
        hit("vscode_task_allow_automatic_tasks_enabled",
            #""task\.allowAutomaticTasks"\s*:\s*"?(on|true)"?"#, severity: 3, options: [.caseInsensitive])

        // `node` invoked against a file with a masquerade-prone
        // (font/wasm-like) extension — the exact TasksJacker+fake-font
        // combo, visible even without fetching the referenced file's own
        // blob content (see BinaryMasqueradeScanner.swift for that side).
        hit("vscode_task_node_on_nonjs_asset",
            #""command"\s*:\s*"node"[\s\S]{0,200}\.(woff2?|ttf|otf|wasm)\b"#, severity: 3)

        // Known C2 infrastructure for this campaign (blockchain RPC
        // endpoints used as a covert channel; vercel-hosted config
        // droppers). A domain substring alone isn't proof by itself —
        // vercel.app in particular has enormous legitimate use — so this
        // stays corroborating, never an auto-revert trigger on its own.
        hit("vscode_task_known_c2_domain",
            #"vercel\.app/settings/|trongrid|aptoslabs|bsc-dataseed|bsc-rpc\.publicnode"#,
            severity: 2, options: [.caseInsensitive])

        // Generic pipe-to-shell (curl|wget ... | sh/bash) already fires
        // from MaliciousCodeHeuristics.contentRules for any file,
        // tasks.json included — not duplicated here.

        return out
    }
}
