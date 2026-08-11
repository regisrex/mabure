//
//  GitRevertEngine.swift
//  mabured
//
//  Orchestrates the post-completion scan-and-revert for one finished git
//  pull/merge: resolve the "before" ref, diff, run heuristics, and either
//  log clean/ambiguous or back up + revert + log. This is GitGuard's
//  KillEngine.swift analog.
//
//  Runs OFF the 100ms scanQueue (see main.swift wiring) — a slow su+git
//  subprocess or a large diff must never delay the next node-e tick.
//

import Darwin
import Foundation

enum GitRevertEngine {
    static func handle(op: TrackedGitOp, config: Config, tracker: GitProcessTracker) {
        guard tracker.markInFlight(op.repoPath) else {
            EventLogger.logGitSkippedConcurrent(repoPath: op.repoPath)
            return
        }
        defer { tracker.clearInFlight(op.repoPath) }

        let eventID = UUID().uuidString

        // "Before" ref: prefer git's own ORIG_HEAD (empirically verified
        // reliable for pull/merge/rebase-pull — see plan), cross-checked
        // against our own pre-op capture; fall back to that capture if
        // ORIG_HEAD is absent or looks stale (e.g. unchanged from HEAD).
        let origHead = GitShell.revParse(ref: "ORIG_HEAD", repoPath: op.repoPath, uid: op.uid)
        guard let newHead = GitShell.revParse(ref: "HEAD", repoPath: op.repoPath, uid: op.uid) else {
            EventLogger.logGitRevertFailed(eventID: eventID, op: op, stage: "rev_parse_head_failed")
            return
        }

        let baseSHA: String
        if let origHead, origHead != newHead {
            baseSHA = origHead
        } else if let pre = op.preOpHeadSHA, pre != newHead {
            baseSHA = pre
        } else {
            // No change (e.g. "Already up to date.") — nothing to scan.
            return
        }

        let (diffResultOpt, diffFailureReason) = GitDiffScanner.diff(oldSHA: baseSHA, newSHA: newHead, repoPath: op.repoPath, uid: op.uid)
        guard let diffResult = diffResultOpt else {
            EventLogger.logGitRevertFailed(eventID: eventID, op: op, stage: "diff_failed:\(diffFailureReason ?? "?")")
            return
        }

        var matched: [MatchedRule] = []
        for file in diffResult.files {
            matched += MaliciousCodeHeuristics.evaluate(file, maxScanBytes: config.git_scan_max_file_size_kb * 1024)
        }
        // Binary-masquerade check (fake fonts/wasm/images hiding a JS
        // loader) needs its own git call per suspicious file, since a
        // true-binary diff carries no added-lines text for the rules
        // above to see in the first place.
        matched += BinaryMasqueradeScanner.evaluate(files: diffResult.files, repoPath: op.repoPath, newSHA: newHead, uid: op.uid)

        let severity3 = matched.filter { $0.severity >= 3 }
        let severity2 = matched.filter { $0.severity == 2 }
        let shouldRevert = !severity3.isEmpty || severity2.count >= 2

        guard shouldRevert, config.git_revert_on_detect, config.git_guard_enabled else {
            if !matched.isEmpty {
                EventLogger.logGitScanAmbiguous(
                    eventID: eventID, op: op, base: baseSHA, head: newHead,
                    matchedRules: matched.map { "\($0.name):\($0.filePath)" }
                )
            } else {
                EventLogger.logGitScanClean(eventID: eventID, op: op, base: baseSHA, head: newHead)
            }
            return
        }

        // Backup the full diff BEFORE reverting — root-owned, so evidence
        // survives even though the content is about to be discarded.
        let backupPath = "\(MaburePaths.gitBackupDir)/\(eventID).patch"
        writeBackupPatch(rawText: diffResult.rawText, to: backupPath)

        // Safety net — near-zero cost even on a clean fast-forward pull,
        // which shouldn't have had conflicting uncommitted changes to begin
        // with, but this preserves anything unexpected rather than
        // silently discarding it in the hard reset below.
        _ = GitShell.run(uid: op.uid, repoPath: op.repoPath, gitArgs: ["stash", "--include-untracked"])

        let resetRes = GitShell.run(uid: op.uid, repoPath: op.repoPath, gitArgs: ["reset", "--hard", baseSHA])
        let reverted = resetRes?.exitCode == 0

        EventLogger.logGitBlock(
            eventID: eventID, op: op, baseSHA: baseSHA, headSHA: newHead,
            matchedRules: matched.map { "\($0.name):\($0.filePath)" },
            reverted: reverted, backupPatchPath: backupPath
        )
        if !reverted {
            EventLogger.logGitRevertFailed(eventID: eventID, op: op, stage: "reset_hard_failed:\(resetRes?.stderr.prefix(200) ?? "?")")
        }
    }

    private static func writeBackupPatch(rawText: String, to path: String) {
        try? FileManager.default.createDirectory(
            atPath: (path as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        FileManager.default.createFile(
            atPath: path, contents: Data(rawText.utf8),
            attributes: [.posixPermissions: 0o600]
        )
    }
}
