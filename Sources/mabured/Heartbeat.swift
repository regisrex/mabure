//
//  Heartbeat.swift
//  mabured
//
//  Emits a periodic log line so the menu-bar agent can distinguish "daemon
//  paused" from "daemon dead" — without this, a crashed daemon would look
//  identical to a quiet, healthy one from the agent's point of view.
//

import Foundation

final class Heartbeat {
    private var last = Date.distantPast

    func emitIfDue(intervalSeconds: Int) {
        let now = Date()
        guard now.timeIntervalSince(last) >= TimeInterval(intervalSeconds) else { return }
        last = now
        EventLogger.logHeartbeat()
    }
}
