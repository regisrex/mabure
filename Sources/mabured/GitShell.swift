//
//  GitShell.swift
//  mabured
//
//  The ONLY place that constructs a shell command string for GitGuard.
//  Every git invocation (rev-parse, diff, stash, reset) runs as the
//  repo-owning uid via `su`, never as root — both to avoid mutating
//  another user's files as root, and because git's "detected dubious
//  ownership" safety check compares the repo directory's owner against the
//  process's EFFECTIVE uid: running as root against a non-root-owned repo
//  trips that check on EVERY git subcommand, not just mutating ones, so
//  rev-parse/diff need the su-wrapper too, not just reset --hard.
//
//  `man su`'s own EXAMPLES section confirms: "You will be asked for
//  operator's password unless your real UID is 0" — root invoking
//  `su <user> -c <cmd>` is unconditionally passwordless (verified directly
//  against the installed man page on this machine, not assumed).
//
//  Escaping strategy: the ONLY dynamic, potentially attacker-influenced
//  string that ever reaches a shell here is the repo's own path (resolved
//  from libproc/-C argv — never from file *contents* or filenames inside
//  the repo). Refs are resolved to SHA hex and regex-validated before ever
//  appearing in a shell string, so no ref value can carry shell
//  metacharacters. Per-file diff content/filenames are never fed into a
//  shell command — one whole-repo `git diff old new` is fetched as text and
//  parsed entirely in Swift (GitDiffScanner).
//

import Foundation

enum GitShell {
    private static let shaHexPattern = try! NSRegularExpression(pattern: "^[0-9a-f]{40,64}$")

    static func isValidSHA(_ s: String) -> Bool {
        shaHexPattern.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }

    /// Single-quotes `s` for safe embedding as ONE token in a POSIX shell
    /// command string. Closing+reopening the quote around a literal quote
    /// (`'\''`) is the standard bulletproof approach — single quotes
    /// disable ALL shell interpretation (`$`, backticks, `;`, newlines,
    /// globs) except for the single-quote character itself, which this
    /// handles explicitly.
    static func posixQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    struct Result {
        let exitCode: Int32
        let stdout: String
        let stderr: String
    }

    /// Runs `git <gitArgs>` inside `repoPath`, as `uid`'s user, via
    /// `su -m <user> -c '<command>'`.
    ///
    /// `-m` keeps root's environment/shell to interpret -c (a normal,
    /// always-present shell) while su has already setuid()'d the process to
    /// the target uid before that shell execs — so the command genuinely
    /// runs with the target's privileges (satisfying git's ownership check)
    /// without depending on the target account having a valid login shell
    /// (`man su`: the "invalid shell" failure mode is itself waived only
    /// when the caller's real uid is 0, which mabured's is).
    ///
    /// Explicit `-c user.name=/-c user.email=` overrides avoid a "Please
    /// tell me who you are" failure from `git stash` (which creates a real
    /// commit object) — root's $HOME (unmodified by -m) has no git identity
    /// configured for this repo/user.
    ///
    /// `Process.arguments` is used for the OUTER `su` call — no shell is
    /// invoked to run `su` itself, so `username` (from getpwuid, not
    /// attacker-controlled) and the literal flags never pass through any
    /// shell parsing. The only string ever handed to a shell is `command`,
    /// built exclusively from a fixed prefix, the quoted repo path, and
    /// individually-quoted git args (subcommand names, flag literals, and
    /// pre-validated SHA strings) — filenames are never placed in it.
    static func run(uid: uid_t, repoPath: String, gitArgs: [String]) -> Result? {
        let username = ProcessScanner.username(forUID: uid)
        guard !username.isEmpty, username != String(uid) else {
            // username(forUID:) falls back to the numeric uid string on
            // lookup failure — treat that as "couldn't resolve", not a
            // real username to su into.
            return nil
        }

        var command = "/usr/bin/git -C \(posixQuote(repoPath)) -c user.name=mabure -c user.email=mabure-gitguard@localhost"
        for arg in gitArgs {
            command += " " + posixQuote(arg)
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/su")
        proc.arguments = ["-m", username, "-c", command]
        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe

        do {
            try proc.run()
        } catch {
            return nil
        }
        proc.waitUntilExit()

        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        return Result(
            exitCode: proc.terminationStatus,
            stdout: String(decoding: outData, as: UTF8.self),
            stderr: String(decoding: errData, as: UTF8.self)
        )
    }

    /// `git rev-parse <ref>`, validated to look like a real SHA before being
    /// trusted anywhere else — defense in depth even though it came from
    /// git's own stdout, not directly from attacker input.
    static func revParse(ref: String, repoPath: String, uid: uid_t) -> String? {
        guard let res = run(uid: uid, repoPath: repoPath, gitArgs: ["rev-parse", ref]),
              res.exitCode == 0
        else { return nil }
        let sha = res.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return isValidSHA(sha) ? sha : nil
    }
}
