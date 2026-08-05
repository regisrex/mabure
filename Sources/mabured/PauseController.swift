//
//  PauseController.swift
//  mabured
//
//  Soft-pause mechanism: a sentinel file the daemon checks every tick.
//  Writable by members of the `_mabure` group (see plan §7-§8) without
//  sudo, so pausing/resuming detection doesn't require a privileged prompt
//  each time — a deliberate convenience/security trade-off, documented in
//  the plan's risk section.
//

import Foundation

enum PauseController {
    static func isPaused() -> Bool {
        FileManager.default.fileExists(atPath: MaburePaths.pauseSentinelPath)
    }
}
