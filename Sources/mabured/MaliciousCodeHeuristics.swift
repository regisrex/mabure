//
//  MaliciousCodeHeuristics.swift
//  mabured
//
//  Local heuristic rules over newly-added diff content, informed by real
//  2025-2026 supply-chain incidents (nx, keyv, AsyncAPI compromises): auto-run
//  lifecycle scripts, decode-then-execute chains, pipe-to-shell, and
//  credential exfiltration. Deliberately NOT a general obfuscation detector
//  or ML classifier — narrow, explainable, fast regexes. Real false
//  positives and real misses are expected, same as EvalMatcher's own
//  documented limitations for the node-e path.
//

import Foundation

struct MatchedRule {
    let name: String
    let filePath: String
    let severity: Int      // 3 = high-confidence/acts alone; 2 = needs corroboration
    let snippet: String    // short excerpt for the log, never the full body
}

/// Shared by MaliciousCodeHeuristics (general behavioral rules) and
/// PolinRiderMarkers.swift (campaign-specific literal IOCs) — one place
/// for "does this regex fire, and if so, package it as a MatchedRule".
enum RegexRuleMatcher {
    static func firstMatch(
        _ name: String, _ pattern: String, in text: String, filePath: String,
        severity: Int, options: NSRegularExpression.Options = []
    ) -> MatchedRule? {
        guard let re = try? NSRegularExpression(pattern: pattern, options: options) else { return nil }
        let range = NSRange(text.startIndex..., in: text)
        guard let m = re.firstMatch(in: text, range: range), let r = Range(m.range, in: text) else { return nil }
        return MatchedRule(name: name, filePath: filePath, severity: severity, snippet: String(text[r].prefix(120)))
    }
}

enum MaliciousCodeHeuristics {
    /// Files whose content is expected to be dense/high-entropy for
    /// legitimate reasons — excluded from entropy/obfuscation rules (but
    /// NOT from the path-based manifest/CI rules) to control false
    /// positives on lockfiles/minified/vendored bundles.
    static func isLowSignalPath(_ path: String) -> Bool {
        let suffixes = [
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
            "go.sum", ".min.js", ".map",
        ]
        return suffixes.contains { path.hasSuffix($0) }
    }

    static func evaluate(_ file: GitDiffFile, maxScanBytes: Int) -> [MatchedRule] {
        guard !file.isBinary else { return [] }  // see BinaryMasqueradeScanner.swift for the binary case

        // Campaign-specific literal IOCs (PolinRiderMarkers) are cheap
        // substring/regex checks with essentially zero legitimate-code
        // false positives, so — unlike the general contentRules below —
        // they run even on low-signal paths (lockfiles, minified bundles)
        // and aren't gated by isLowSignalPath. Still respects the size
        // gate for pathologically large files.
        guard file.byteSize <= maxScanBytes else {
            // Oversized file: still run the cheap path-based rules, skip
            // the O(n) content regexes (performance guard).
            return manifestAndCIRules(file) + PolinRiderMarkers.evaluate(file)
        }
        var rules = manifestAndCIRules(file) + PolinRiderMarkers.evaluate(file)
        if !isLowSignalPath(file.pathB) {
            rules += contentRules(file)
        }
        return rules
    }

    private static func manifestAndCIRules(_ file: GitDiffFile) -> [MatchedRule] {
        var out: [MatchedRule] = []
        let p = file.pathB

        if p.hasSuffix("package.json") {
            for key in ["postinstall", "preinstall", "prepare"] {
                if file.addedLinesText.range(of: "\"\(key)\"") != nil {
                    out.append(MatchedRule(
                        name: "manifest_lifecycle_script_change", filePath: p, severity: 3,
                        snippet: "new/changed \"\(key)\" script in package.json"
                    ))
                }
            }
        }
        if p.hasSuffix("composer.json"), file.addedLinesText.contains("post-install-cmd") {
            out.append(MatchedRule(name: "manifest_lifecycle_script_change", filePath: p, severity: 3,
                                    snippet: "post-install-cmd in composer.json"))
        }

        let ciPatterns = [".github/workflows/", ".gitlab-ci.yml", ".circleci/", ".travis.yml",
                           "azure-pipelines.yml", ".drone.yml", ".git/hooks/", ".githooks/"]
        if ciPatterns.contains(where: { p.contains($0) }) {
            out.append(MatchedRule(name: "ci_or_hook_file_change", filePath: p, severity: 3,
                                    snippet: "CI/hook-relevant file changed: \(p)"))
        }
        if file.addedLinesText.contains("core.hooksPath") {
            out.append(MatchedRule(name: "ci_or_hook_file_change", filePath: p, severity: 3,
                                    snippet: "core.hooksPath reassignment"))
        }
        return out
    }

    private static func contentRules(_ file: GitDiffFile) -> [MatchedRule] {
        let text = file.addedLinesText
        var out: [MatchedRule] = []

        func hit(_ name: String, _ pattern: String, severity: Int, options: NSRegularExpression.Options = []) {
            if let rule = RegexRuleMatcher.firstMatch(name, pattern, in: text, filePath: file.pathB, severity: severity, options: options) {
                out.append(rule)
            }
        }

        // eval/Function() of a decoded/dynamic string.
        hit("eval_dynamic_string",
            #"\b(eval|new\s+Function)\s*\(\s*(atob|Buffer\.from|decodeURIComponent|window\.atob)\s*\("#,
            severity: 3)

        // base64/hex decode -> execute chain.
        hit("base64_or_hex_decode_chain",
            #"(atob|Buffer\.from\([^,]+,\s*['"](base64|hex)['"]\)|base64_decode|b64decode|\[Convert\]::FromBase64String)"#
            + #"[\s\S]{0,80}(eval|exec\(|Function\(|child_process|os\.system|subprocess)"#,
            severity: 3)

        // Pipe-to-shell.
        hit("pipe_to_shell",
            #"(curl|wget)\b[^\n|]*\|\s*(sh|bash|zsh)\b|iex\s*\(|New-Object\s+Net\.WebClient|iwr\b[^\n|]*\|\s*iex"#,
            severity: 3, options: [.caseInsensitive])

        // String.fromCharCode / array-join obfuscation.
        hit("array_join_charcode_obfuscation",
            #"String\.fromCharCode\s*\(\s*\d+\s*(,\s*\d+\s*){5,}\)|\.map\s*\(\s*String\.fromCharCode\s*\)\s*\.join\s*\(\s*['"]"#,
            severity: 2)

        // gzip/zlib inflate stacking.
        hit("gzip_or_zlib_inflate_stack",
            #"(gzinflate|zlib\.decompress|pako\.inflate)\s*\(\s*(base64_decode|atob|Buffer\.from)"#,
            severity: 3)

        // Credential env read -> network sink.
        hit("credential_env_exfil",
            #"(process\.env|os\.environ|ENV\[)[\s\S]{0,120}(TOKEN|SECRET|KEY|PASSWORD|AWS_|NPM_TOKEN|GITHUB_TOKEN)"#
            + #"[\s\S]{0,200}(fetch\(|axios\.|http\.request|requests\.post|XMLHttpRequest)"#,
            severity: 3)

        // Reversed-string stacking feeding a decode/exec sink.
        hit("reversed_string_stacking",
            #"(\.split\(['"]['"]\)\.reverse\(\)\.join\(['"]['"]\)|strrev\()[\s\S]{0,80}(eval|atob|Function\()"#,
            severity: 2)

        // High-entropy long literal — checked in Swift (entropy math), not regex.
        for lit in extractLongStringLiterals(text, minLen: 60) {
            let ent = shannonEntropy(lit)
            if ent >= 4.0 {
                out.append(MatchedRule(name: "high_entropy_obfuscated_literal", filePath: file.pathB, severity: 2,
                                        snippet: "\(lit.prefix(40))… (entropy \(String(format: "%.2f", ent)))"))
                break  // one is enough to flag the file
            }
        }

        return out
    }

    private static func extractLongStringLiterals(_ text: String, minLen: Int) -> [String] {
        guard let re = try? NSRegularExpression(pattern: #"['"]([A-Za-z0-9+/=]{\#(minLen),})['"]"#) else { return [] }
        let range = NSRange(text.startIndex..., in: text)
        return re.matches(in: text, range: range).compactMap {
            guard let r = Range($0.range(at: 1), in: text) else { return nil }
            return String(text[r])
        }
    }

    private static func shannonEntropy(_ s: String) -> Double {
        var freq: [Character: Int] = [:]
        for c in s { freq[c, default: 0] += 1 }
        let n = Double(s.count)
        guard n > 0 else { return 0 }
        return freq.values.reduce(0.0) { acc, count in
            let p = Double(count) / n
            return acc - p * log2(p)
        }
    }
}
