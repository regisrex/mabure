//
//  GitCommandMatcher.swift
//  mabured
//
//  Boundary-aware argv matcher for `git pull`/`git merge`, mirroring
//  EvalMatcher.swift's structure: walk argv skipping git's own global
//  options (some of which take a value) until the first non-flag token,
//  which is the subcommand.
//
//  v1 only tracks "pull" and "merge" (see plan §Context — both set
//  ORIG_HEAD and touch HEAD/working-tree, giving a clean diff+revert
//  story; "fetch" doesn't touch the working tree, "clone" has no
//  ORIG_HEAD — both deliberately out of scope for now). "fetch" is still
//  recognized here so enabling it later is a one-line change in
//  GitProcessTracker, not a re-plumb.
//

/// Git global flags that take a value, either as a separate following
/// token (`-C path`) or glued with `=` (`--git-dir=path`). Source: git(1)
/// SYNOPSIS/OPTIONS.
let gitValueTakingGlobalFlags: Set<String> = [
    "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env",
    "--attr-source",
]

/// Global flags that never take a value.
let gitNoValueGlobalFlags: Set<String> = [
    "-v", "--version", "-h", "--help", "--html-path", "--man-path", "--info-path",
    "-p", "--paginate", "-P", "--no-pager", "--no-replace-objects", "--no-lazy-fetch",
    "--no-optional-locks", "--no-advice", "--bare", "--exec-path", "--literal-pathspecs",
    "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs", "--list-cmds",
]

struct GitMatch {
    /// "pull" | "fetch" | "merge" | any other subcommand (caller decides
    /// what to do with it — the tracker only acts on pull/merge).
    var subcommand: String?
    var subcommandIndex: Int?
    /// Value of the LAST -C seen before the subcommand boundary, if any —
    /// takes precedence over the process's libproc cwd. Multiple -C flags
    /// compose relative to the *preceding* -C per git's own docs; v1 does
    /// not implement that composition (documented, accepted gap — same
    /// spirit as EvalMatcher's own known edges).
    var dashCPath: String?
}

enum GitCommandMatcher {
    /// argv is full argv (argv[0] included) as returned by ArgvParser.
    static func classify(argv: [String]) -> GitMatch {
        var result = GitMatch()
        guard argv.count > 1 else { return result }

        var i = 1
        while i < argv.count {
            let tok = argv[i]

            if tok == "-C" || tok == "-c" {
                if i + 1 < argv.count {
                    if tok == "-C" { result.dashCPath = argv[i + 1] }
                    i += 2
                } else {
                    i += 1
                }
                continue
            }
            if let eq = tok.firstIndex(of: "="),
               gitValueTakingGlobalFlags.contains(String(tok[tok.startIndex..<eq])) {
                i += 1
                continue
            }
            if gitValueTakingGlobalFlags.contains(tok) {
                i += (i + 1 < argv.count) ? 2 : 1
                continue
            }
            if gitNoValueGlobalFlags.contains(tok) {
                i += 1
                continue
            }
            if tok.hasPrefix("-") {
                // Unrecognized global flag shape — conservatively skip just
                // this token (not a guessed value) rather than risk
                // mis-consuming the real subcommand token.
                i += 1
                continue
            }

            // First non-flag token = the subcommand.
            result.subcommand = tok
            result.subcommandIndex = i
            break
        }
        return result
    }
}
