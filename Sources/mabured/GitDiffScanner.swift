//
//  GitDiffScanner.swift
//  mabured
//
//  Fetches one whole-repo unified diff between two resolved SHAs (as the
//  repo-owning user, via GitShell) and parses it into per-file sections in
//  Swift — never re-embeds a filename into a subsequent shell command.
//

import Foundation

struct GitDiffFile {
    let pathA: String
    let pathB: String
    let isNewFile: Bool
    let isBinary: Bool
    /// Every added ("+"-prefixed, excluding the "+++" file header) line,
    /// newline-joined. This is what heuristics scan — never the removed
    /// lines, since those can't be something a fresh pull just introduced.
    let addedLinesText: String
    let byteSize: Int
}

enum GitDiffScanner {
    struct DiffResult {
        let files: [GitDiffFile]
        /// The raw, unparsed diff text — kept so GitRevertEngine can write
        /// an exact backup patch without re-fetching or reconstructing it.
        let rawText: String
    }

    /// On failure, returns a short reason string (never nil) alongside a nil
    /// DiffResult, so callers can log *why* rather than just "it failed" —
    /// this is what caught an invalid-flag bug (`--find-renames=on` isn't
    /// valid git syntax; the flag takes either no value or a percentage)
    /// during live verification instead of leaving it a silent mystery.
    static func diff(oldSHA: String, newSHA: String, repoPath: String, uid: uid_t) -> (result: DiffResult?, failureReason: String?) {
        guard GitShell.isValidSHA(oldSHA), GitShell.isValidSHA(newSHA) else {
            return (nil, "invalid_sha_shape")
        }
        guard let res = GitShell.run(
            uid: uid, repoPath: repoPath,
            // core.quotePath=false: avoid octal-escaped paths for
            // non-ASCII filenames in the diff header (see plan risks).
            gitArgs: ["-c", "core.quotePath=false", "diff", "--no-color", "--find-renames", oldSHA, newSHA]
        ) else {
            return (nil, "su_or_git_invocation_failed")
        }
        guard res.exitCode == 0 else {
            return (nil, "git_diff_exit_\(res.exitCode):\(res.stderr.prefix(200))")
        }

        return (DiffResult(files: parse(res.stdout), rawText: res.stdout), nil)
    }

    static func parse(_ text: String) -> [GitDiffFile] {
        var files: [GitDiffFile] = []
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        var i = 0
        while i < lines.count {
            guard lines[i].hasPrefix("diff --git a/") else { i += 1; continue }
            let header = lines[i]
            var isBinary = false
            var isNewFile = false
            var added: [Substring] = []
            i += 1
            while i < lines.count, !lines[i].hasPrefix("diff --git a/") {
                if lines[i].hasPrefix("new file mode") { isNewFile = true }
                if lines[i].hasPrefix("Binary files") { isBinary = true }
                if lines[i].hasPrefix("+"), !lines[i].hasPrefix("+++") {
                    added.append(lines[i].dropFirst())
                }
                i += 1
            }
            let (a, b) = parseHeaderPaths(header)
            let addedText = added.joined(separator: "\n")
            files.append(GitDiffFile(
                pathA: a, pathB: b, isNewFile: isNewFile, isBinary: isBinary,
                addedLinesText: addedText, byteSize: addedText.utf8.count
            ))
        }
        return files
    }

    /// "diff --git a/foo.txt b/foo.txt" — with core.quotePath=false this
    /// covers the common case; a small residual edge case (a path
    /// containing the literal substring " b/") isn't disambiguated further
    /// in v1 (documented, accepted — affects only path-based rule matching,
    /// never the shell-safety properties, since filenames never reach a
    /// shell command).
    private static func parseHeaderPaths(_ header: Substring) -> (String, String) {
        let s = header.dropFirst("diff --git a/".count)
        guard let bIdx = s.range(of: " b/") else { return (String(s), String(s)) }
        return (String(s[s.startIndex..<bIdx.lowerBound]), String(s[bIdx.upperBound...]))
    }
}
