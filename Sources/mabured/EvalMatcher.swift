//
//  EvalMatcher.swift
//  mabured
//
//  Decides whether a `node` process's argv represents an inline-eval
//  invocation (`node -e "..."` / `node --eval ...`), replicating Node's own
//  CLI-parsing boundary rather than doing a naive whole-argv substring scan.
//
//  Known, accepted limitation (see plan §10): this matches on argv *shape*,
//  not on what code Node will actually execute. `node -e -- "payload"` is a
//  real false positive — Node treats the literal "--" token right after -e
//  as the eval body, so "payload" never runs, but the matcher still sees
//  "-e followed by a token" and fires. Not worth a full Node-argument-value
//  emulator to close.
//

/// Node CLI flags that consume the *next* argv token as their own value
/// (so that token must never be mistaken for the script path or an eval
/// flag). Source: Node's option table (node_options.cc). This list is
/// necessarily maintained against Node's supported flag surface — re-check
/// it when bumping the range of Node versions this tool is expected to see.
let nodeValueTakingFlags: Set<String> = [
    "-r", "--require",
    "-C", "--conditions",
    "--loader", "--experimental-loader",
    "--experimental-policy",
    "--experimental-specifier-resolution",
    "--openssl-config",
    "--icu-data-dir",
    "--redirect-warnings",
    "--diagnostic-dir",
    "--cpu-prof-dir", "--cpu-prof-name",
    "--heap-prof-dir", "--heap-prof-name",
    "--title",
    "--input-type",
    "--tls-cipher-list",
    "--use-largepages",
]

struct EvalMatch {
    /// A real match found before Node's own flag-parsing boundary (script
    /// path or `--` terminator). Present => kill.
    var boundary: (token: String, index: Int)?
    /// A flag-shaped match found anywhere in argv, including past the
    /// boundary where it would actually belong to the script, not node.
    /// Used only for observability (`ambiguous_no_kill`), never to kill.
    var naive: (token: String, index: Int)?
}

enum EvalMatcher {

    private static func isEvalFlag(_ tok: String, flags: [String]) -> Bool {
        if flags.contains(tok) { return true }
        if flags.contains(where: { $0.hasSuffix("=") && tok.hasPrefix($0) }) { return true }
        return false
    }

    /// `argv` is the full argv as returned by ArgvParser (argv[0] included).
    static func classify(argv: [String], matchedFlags: [String]) -> EvalMatch {
        var result = EvalMatch()
        guard argv.count > 1 else { return result }

        var i = 1  // skip argv[0] — identity is proc_pidpath, never argv[0]
        var sawScriptPathOrTerminator = false

        while i < argv.count {
            let tok = argv[i]

            if sawScriptPathOrTerminator {
                // Past node's own flag parsing — anything here belongs to
                // the script, not node. Still scanned for observability.
                if result.naive == nil, isEvalFlag(tok, flags: matchedFlags) {
                    result.naive = (tok, i)
                }
                i += 1
                continue
            }

            // POSIX options terminator: Node stops parsing its own flags
            // here. `node -- -e "text"` must NOT match — `-e` becomes a
            // literal script filename argument, not a flag.
            if tok == "--" {
                sawScriptPathOrTerminator = true
                i += 1
                continue
            }

            if isEvalFlag(tok, flags: matchedFlags) {
                result.boundary = (tok, i)
                if result.naive == nil { result.naive = (tok, i) }
                break
            }

            if tok.hasPrefix("-") {
                i += nodeValueTakingFlags.contains(tok) ? 2 : 1
                continue
            }

            // First non-flag token = the script path; everything after is
            // the script's own argv, not node's.
            sawScriptPathOrTerminator = true
            i += 1
        }

        return result
    }
}
