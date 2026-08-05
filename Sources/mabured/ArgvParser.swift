//
//  ArgvParser.swift
//  mabured
//
//  Fetches and parses a process's argv via the undocumented-but-decades-stable
//  Darwin sysctl(CTL_KERN, KERN_PROCARGS2, pid) call. This is how ps/top/
//  Activity Monitor themselves get argv (there is no supported libproc
//  equivalent), so it's a well-trodden path despite lacking a man page.
//
//  Buffer layout returned by the kernel:
//    [ 4 bytes: argc (native-endian Int32) ]
//    [ exec_path C-string, NUL-terminated ]
//    [ 0..N NUL padding/alignment bytes ]
//    [ argv[0] NUL-terminated ] [ argv[1] ] ... [ argv[argc-1] ]
//    [ further NULs, then envp, then an Apple[] vector — ignored here ]
//

import Darwin

enum ArgvParser {

    /// Queries ARG_MAX once at daemon startup. Callers should allocate one
    /// scratch buffer of this size and reuse it every tick.
    static func queryArgMax() -> Int32 {
        var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]
        var argMax: Int32 = 0
        var size = MemoryLayout<Int32>.size
        let ret = sysctl(&mib, 2, &argMax, &size, nil, 0)
        // Fall back to a conservative default if the query itself fails —
        // extremely unlikely, but a hot loop must never crash on this.
        return ret == 0 && argMax > 0 ? argMax : (256 * 1024)
    }

    /// Fetches and parses argv for `pid` into a reused scratch buffer of
    /// `argMax` bytes. Returns nil if the process has already exited (ESRCH)
    /// or the buffer couldn't be parsed.
    ///
    /// IMPORTANT: because `scratch` is reused across calls, we always reset
    /// the in/out `size` parameter to the buffer's full capacity immediately
    /// before the syscall (sysctl overwrites it with the actual byte count
    /// written) and clip all parsing to that returned size — never to the
    /// buffer's capacity. Skipping that clip would let stale bytes from a
    /// previous, larger process's argv bleed into a shorter result.
    static func fetch(pid: pid_t, argMax: Int32, scratch: UnsafeMutableRawPointer) -> [String]? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = Int(argMax)
        let ret = sysctl(&mib, 3, scratch, &size, nil, 0)
        guard ret == 0, size > MemoryLayout<Int32>.size else { return nil }
        return parse(scratch, length: size)
    }

    private static func parse(_ buf: UnsafeMutableRawPointer, length: Int) -> [String]? {
        let end = buf + length

        // argc is not guaranteed to be pointer-aligned in this buffer.
        let argc = Int(buf.loadUnaligned(as: Int32.self))
        guard argc > 0 else { return [] }

        var cursor = buf + MemoryLayout<Int32>.size

        func readCString(from start: UnsafeMutableRawPointer) -> (String, UnsafeMutableRawPointer)? {
            var p = start
            while p < end, p.load(as: UInt8.self) != 0 { p += 1 }
            guard p < end else { return nil }
            let s = String(cString: start.assumingMemoryBound(to: CChar.self))
            return (s, p + 1)
        }

        // exec_path — discarded (we use proc_pidpath for identity, not this).
        guard let (_, afterPath) = readCString(from: cursor) else { return nil }
        cursor = afterPath

        // Skip alignment NUL padding between exec_path and argv[0].
        while cursor < end, cursor.load(as: UInt8.self) == 0 { cursor += 1 }

        var argv: [String] = []
        argv.reserveCapacity(argc)
        for _ in 0..<argc {
            guard let (s, next) = readCString(from: cursor) else { break }
            argv.append(s)
            cursor = next
        }
        return argv
    }
}
