//
//  PauseToggle.swift
//  Mabure (menu bar agent)
//
//  Writes/removes the pause sentinel file the daemon checks every tick.
//  Requires the invoking user to be a member of the `_mabure` group (added
//  by install.sh) AND to have logged in fresh since being added — group
//  membership is cached in the login session's credential, so the very
//  first attempt right after install can legitimately fail. That's
//  surfaced to the user as an alert rather than failing silently.
//

import Foundation

enum PauseToggle {
    static var isPaused: Bool {
        FileManager.default.fileExists(atPath: AgentPaths.pauseSentinelPath)
    }

    /// Returns nil on success, or a human-readable error message on failure.
    static func setPaused(_ paused: Bool) -> String? {
        let path = AgentPaths.pauseSentinelPath
        if paused {
            let created = FileManager.default.createFile(atPath: path, contents: Data())
            if !created {
                return "Couldn't pause — you may need to log out and back in after install " +
                       "for _mabure group membership to take effect."
            }
        } else {
            if FileManager.default.fileExists(atPath: path) {
                do {
                    try FileManager.default.removeItem(atPath: path)
                } catch {
                    return "Couldn't resume — you may need to log out and back in after install " +
                           "for _mabure group membership to take effect. (\(error.localizedDescription))"
                }
            }
        }
        return nil
    }
}
