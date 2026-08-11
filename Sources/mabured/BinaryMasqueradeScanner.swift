//
//  BinaryMasqueradeScanner.swift
//  mabured
//
//  PolinRider (and similar campaigns) hide JS loaders inside files with
//  binary-looking extensions (.woff2, .woff, .ttf, .wasm, .png, ...) — git
//  itself detects these as binary and a plain `git diff` shows only
//  "Binary files ... differ" with NO content at all, so
//  MaliciousCodeHeuristics' added-lines-text scanning never even sees
//  what's inside. This does one extra, narrowly-scoped step: for files git
//  flagged as binary in the diff AND whose extension is masquerade-prone,
//  fetch the actual blob content (`git show <sha>:<path>`) and check for
//  JS-loader-shaped text where a real font/wasm/image file's binary header
//  should be. A real .woff2/.wasm/.png never contains the literal text
//  "require(" or "child_process" — finding it at all is a near-zero-
//  false-positive masquerade signal.
//

import Foundation

private let masqueradeProneExtensions: Set<String> = [
    "woff", "woff2", "ttf", "otf", "eot", "wasm",
    "png", "jpg", "jpeg", "gif", "ico", "webp",
]

enum BinaryMasqueradeScanner {
    /// Only files GitDiffScanner already flagged `isBinary` are considered
    /// — this never re-fetches/re-scans a file that already had its added-
    /// lines text handled by MaliciousCodeHeuristics.
    static func evaluate(files: [GitDiffFile], repoPath: String, newSHA: String, uid: uid_t) -> [MatchedRule] {
        var out: [MatchedRule] = []
        for file in files {
            guard file.isBinary else { continue }
            let ext = (file.pathB as NSString).pathExtension.lowercased()
            guard masqueradeProneExtensions.contains(ext) else { continue }

            // git's `<rev>:<path>` blob-addressing syntax — path is passed
            // as a single already-quoted gitArg element (GitShell.run
            // POSIX-quotes every element individually), so an arbitrary/
            // attacker-influenced filename here is exactly as safe as any
            // other gitArg elsewhere in this codebase, not a special case.
            guard let res = GitShell.run(
                uid: uid, repoPath: repoPath, gitArgs: ["show", "\(newSHA):\(file.pathB)"]
            ), res.exitCode == 0 else { continue }

            // Raw blob bytes decoded lossily as UTF-8 — fine here, since
            // we're only looking for plain-ASCII loader markers, which
            // survive lossy decoding intact regardless of what surrounds
            // them in the real binary payload.
            if let rule = suspiciousContentRule(in: res.stdout, filePath: file.pathB, ext: ext) {
                out.append(rule)
            }
        }
        return out
    }

    static func suspiciousContentRule(in content: String, filePath: String, ext: String) -> MatchedRule? {
        let markers = ["require(", "child_process", "process.env", "eval(", "atob(", "global['_V']", "global[\"_V\"]"]
        for marker in markers where content.contains(marker) {
            return MatchedRule(
                name: "binary_masquerade_js_content", filePath: filePath, severity: 3,
                snippet: "\(filePath) (.\(ext)) contains \"\(marker)\" — a real .\(ext) file never does"
            )
        }
        return nil
    }
}
