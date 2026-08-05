//
//  ProcessScanner.swift
//  mabured
//
//  Thin wrappers over libproc for enumerating pids and reading per-pid
//  metadata (executable path, ppid, uid, start time). No argv here — that's
//  ArgvParser's job, since it needs the raw sysctl(KERN_PROCARGS2) path
//  instead of libproc.
//

import Darwin
import Foundation

enum ProcessScanner {

    /// All currently-running pids on the system. Over-allocates to absorb
    /// processes created between the size query and the fill call (a fork
    /// storm can grow the table between those two syscalls).
    static func listAllPids() -> [pid_t] {
        let initialCount = proc_listallpids(nil, 0)
        guard initialCount > 0 else { return [] }

        let capacity = Int(initialCount) + 512
        var pids = [pid_t](repeating: 0, count: capacity)
        let filled = pids.withUnsafeMutableBytes { buf -> Int32 in
            proc_listallpids(buf.baseAddress, Int32(buf.count))
        }
        guard filled > 0 else { return [] }
        return Array(pids.prefix(Int(filled))).filter { $0 != 0 }
    }

    /// PROC_PIDPATHINFO_MAXSIZE (4*MAXPATHLEN) — the macro itself isn't
    /// Swift-importable (it's a function-like arithmetic expression over
    /// MAXPATHLEN), so its value is inlined here directly.
    private static let pidPathInfoMaxSize = 4 * 1024

    /// The real, kernel-resolved executable path for a pid (vnode-derived —
    /// cannot be spoofed by the process rewriting argv[0]/process.title).
    /// Returns nil if the pid has already exited (benign, common race).
    static func execPath(of pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: pidPathInfoMaxSize)
        let n = proc_pidpath(pid, &buffer, UInt32(pidPathInfoMaxSize))
        guard n > 0 else { return nil }
        return String(cString: buffer)
    }

    /// Basename of execPath(pid), used as the trustworthy identity check.
    static func execBasename(of pid: pid_t) -> String? {
        guard let path = execPath(of: pid) else { return nil }
        return (path as NSString).lastPathComponent
    }

    struct BSDInfo {
        let pid: pid_t
        let ppid: pid_t
        let uid: uid_t
        /// Process start time as seconds+microseconds since the epoch.
        let startTimeSec: Int64
        let startTimeUsec: Int64
    }

    /// ppid/uid/start-time via proc_pidinfo(PROC_PIDTBSDINFO). Returns nil if
    /// the pid has already exited (ESRCH) — callers should treat this as
    /// "process is gone, skip it", not as an error worth logging loudly.
    static func bsdInfo(of pid: pid_t) -> BSDInfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        let ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
        guard ret == size else { return nil }
        return BSDInfo(
            pid: pid,
            ppid: pid_t(info.pbi_ppid),
            uid: uid_t(info.pbi_uid),
            startTimeSec: Int64(info.pbi_start_tvsec),
            startTimeUsec: Int64(info.pbi_start_tvusec)
        )
    }

    /// Direct ppid lookup (cheaper than bsdInfo when that's all that's needed,
    /// e.g. finding children of a just-killed pid).
    static func ppid(of pid: pid_t) -> pid_t? {
        bsdInfo(of: pid)?.ppid
    }

    static func username(forUID uid: uid_t) -> String {
        if let pw = getpwuid(uid), let namePtr = pw.pointee.pw_name {
            return String(cString: namePtr)
        }
        return String(uid)
    }

    /// The live process's current working directory, via
    /// proc_pidinfo(PROC_PIDVNODEPATHINFO) — the same libproc technique
    /// lsof/fs_usage use to report a process's cwd. Used by GitGuard to
    /// resolve which repo a `git pull`/`merge` invocation is operating on.
    /// Returns nil if the pid has exited or the call fails. Note: the
    /// kernel's vip_path field is documented as "tail end of it" — for a
    /// path longer than MAXPATHLEN (1024 bytes) it may be truncated. Not
    /// defended against here; accepted as vanishingly unlikely for real
    /// repo checkouts (see plan risks).
    static func cwd(of pid: pid_t) -> String? {
        var info = proc_vnodepathinfo()
        let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
        let ret = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, size)
        guard ret == size else { return nil }
        return withUnsafeBytes(of: info.pvi_cdir.vip_path) { raw -> String? in
            raw.baseAddress.map { String(cString: $0.assumingMemoryBound(to: CChar.self)) }
        }
    }
}
