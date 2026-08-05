//
//  KillEngine.swift
//  mabured
//
//  The decide-and-kill path for a single newly-observed `node` pid. Kept
//  deliberately minimal (enumerate/match/kill/log raw facts only) since
//  every local user fully controls the argv fed into this root-privileged
//  code path — formatting/redaction for display lives in the unprivileged
//  agent, not here.
//

import Darwin
import Foundation

enum KillEngine {
    static func handle(
        newPid pid: pid_t, config: Config, allowlist: Allowlist,
        argMax: Int32, scratch: UnsafeMutableRawPointer
    ) {
        guard ProcessScanner.execBasename(of: pid) == "node" else { return }
        guard let argv = ArgvParser.fetch(pid: pid, argMax: argMax, scratch: scratch),
              argv.count > 1 else { return }

        let match = EvalMatcher.classify(argv: argv, matchedFlags: config.matched_flags)
        guard let hit = match.boundary else {
            if let naive = match.naive {
                EventLogger.logAmbiguous(pid: pid, argv: argv, naiveToken: naive.token)
            }
            return
        }

        // Process may have exited between listing and here — benign race.
        guard let meta1 = ProcessScanner.bsdInfo(of: pid) else { return }

        let eventID = UUID().uuidString
        let allowlisted = AllowlistChecker.matches(pid: pid, argv: argv, meta: meta1, allowlist: allowlist)

        if config.dry_run || !config.kill_enabled || allowlisted {
            EventLogger.logMatch(
                eventID: eventID, pid: pid, argv: argv, meta: meta1, matchedToken: hit.token,
                killed: false, allowlisted: allowlisted, dryRun: config.dry_run,
                reason: allowlisted ? "allowlisted" : "dry_run_or_disabled"
            )
            return
        }

        // TOCTOU re-check: re-verify the process's start time immediately
        // before kill(). If it differs, the original pid has already exited
        // and this pid number has been reused by an unrelated process —
        // abort rather than kill the wrong thing.
        guard let meta2 = ProcessScanner.bsdInfo(of: pid),
              meta2.startTimeSec == meta1.startTimeSec,
              meta2.startTimeUsec == meta1.startTimeUsec
        else {
            EventLogger.logPidReusedAbort(eventID: eventID, pid: pid, argv: argv)
            return
        }

        // Snapshot children now (covers a synchronously-forking one-liner)
        // before killing the parent.
        let children: [pid_t] = config.kill_children
            ? ProcessScanner.listAllPids().filter { ProcessScanner.ppid(of: $0) == pid }
            : []

        let killRet = kill(pid, SIGKILL)
        let killErrno = killRet == 0 ? nil : errno
        let killTS = Date()

        EventLogger.logMatch(
            eventID: eventID, pid: pid, argv: argv, meta: meta1, matchedToken: hit.token,
            killed: killRet == 0, killErrno: killErrno, killTS: killTS, children: children
        )

        for child in children {
            guard let cmeta = ProcessScanner.bsdInfo(of: child) else { continue }
            let cret = kill(child, SIGKILL)
            EventLogger.logChildKill(parentEventID: eventID, pid: child, meta: cmeta, killed: cret == 0)
        }
    }
}
