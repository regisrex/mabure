//
//  PolinRiderMarkers.swift
//  mabured
//
//  High-confidence, campaign-specific indicators for the PolinRider /
//  TasksJacker DPRK supply-chain campaign — active since ~2026H1, expanding
//  across npm, Packagist, Go modules, and the Chrome Web Store (108+
//  malicious packages / 1,950+ affected repos as of the most recent public
//  reporting). Kept in its own file, separate from MaliciousCodeHeuristics
//  .swift's general behavioral rules: these are near-zero-false-positive
//  literal artifacts pulled from real observed samples, not generic
//  patterns — treat a single hit here as materially stronger evidence than
//  a single generic content-rule hit.
//
//  Cross-checked against independent public sources before anything here
//  was added — never hardcode an unverified "IOC" as an auto-revert
//  trigger on a single unconfirmed claim:
//    - https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands
//    - https://opensourcemalware.com/blog/tasksjacker-blog-post
//    - an independently published community IOC scanner that documents
//      the same literal marker strings used below (rmcej%otb%,
//      Cot%3t=shtP, global['!']=, global['_V']=), cross-referenced rather
//      than trusted on a single source's say-so.
//
//  These are point-in-time artifacts, not structural properties of
//  malicious code (unlike MaliciousCodeHeuristics.swift's behavioral
//  rules, which target patterns that don't change build-to-build) —
//  revisit/expand this file as the campaign evolves. Exact obfuscator-
//  generated identifier names are deliberately NOT hardcoded here (e.g. a
//  specific sample's decoder function name) since those typically
//  regenerate per build; the *shape* rule below generalizes across
//  variants the way a literal name would not.
//

import Foundation

enum PolinRiderMarkers {
    static func evaluate(_ file: GitDiffFile) -> [MatchedRule] {
        let text = file.addedLinesText
        guard !text.isEmpty else { return [] }
        var out: [MatchedRule] = []

        func hit(_ name: String, _ pattern: String, severity: Int, options: NSRegularExpression.Options = []) {
            if let rule = RegexRuleMatcher.firstMatch(name, pattern, in: text, filePath: file.pathB, severity: severity, options: options) {
                out.append(rule)
            }
        }

        // Literal packed-string fragments pulled from real PolinRider
        // samples (both known variants) — essentially zero legitimate
        // usage of these exact substrings.
        hit("polinrider_packed_string_v1", #"rmcej%otb%"#, severity: 3)
        hit("polinrider_packed_string_v2", #"Cot%3t=shtP"#, severity: 3)

        // global['!']= / global['_V']= — specific injection keys observed
        // across both known variants. Value suffixes (e.g. what's assigned
        // to global['_V']) aren't matched since they vary per build; the
        // injection KEY itself is the stable signal.
        hit("polinrider_global_bang_key", #"global\s*\[\s*['"]!['"]\s*\]\s*="#, severity: 3)
        hit("polinrider_global_v_key", #"global\s*\[\s*['"]_V['"]\s*\]\s*="#, severity: 3)

        // require/module stashed into a 1-char global[] key — a classic
        // move to survive across module boundaries while staying
        // grep-unfriendly. Kept at severity 2 (needs corroboration), same
        // as originally scoped — this specific shape has a very slightly
        // higher (though still low) chance of legitimate-shim overlap
        // than the literal/exact-key markers above.
        hit("polinrider_global_require_module_stash",
            #"global\s*\[\s*['"]r['"]\s*\]\s*=\s*require|global\s*\[\s*['"]m['"]\s*\]\s*=\s*module"#,
            severity: 2)

        // Leaked build-environment/persistence artifacts seen in specific
        // samples — an SSH-key comment string and a macOS LaunchAgent
        // label (relevant since Mabure itself is macOS-focused).
        hit("polinrider_ssh_key_artifact", #"bink@DESKTOP-N8JGD6T"#, severity: 3)
        hit("polinrider_macos_launchagent_artifact", #"com\.bablu\.helper\.plist"#, severity: 3)

        // Rotating obfuscator identifier SHAPE — not a specific literal
        // name (the exact identifier regenerates per build/campaign wave,
        // so matching the shape generalizes the way a hardcoded name like
        // a single sample's decoder function name would not). This shape
        // is also produced by the legitimate `javascript-obfuscator` npm
        // package for non-malicious reasons, so it's corroborating
        // evidence only — never an auto-revert trigger by itself.
        hit("obfuscator_hex_suffixed_identifier", #"\b_\$_[0-9a-f]{4}\b|\b_0x[0-9a-f]{4,6}\b"#, severity: 2)

        return out
    }
}
