//
//  AppDelegate.swift
//  Mabure (menu bar agent)
//
//  Wires together: LaunchServices self-registration + notification
//  authorization, the log tailer, the status item/menu, the pause toggle,
//  and a watchdog that flips the icon to "daemon unreachable" if no
//  daemon activity (heartbeat/state_change/kill) has been seen recently.
//

import AppKit
import UserNotifications

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    private var controller: StatusItemController!
    private var tailer: LogTailer!
    private var watchdogTimer: Timer?
    private var lastDaemonActivity = Date.distantPast

    // Matches mabured's Config defaults (plan §2) — the agent doesn't parse
    // config.json itself; if these are tuned in production, the watchdog's
    // unreachable threshold just runs a bit loose/tight relative to it,
    // which only affects how quickly the icon flips, not correctness.
    private let heartbeatIntervalS: TimeInterval = 10
    private let unreachableAfterMissed = 2

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Self-register with LaunchServices at runtime. Without this, a
        // raw-execve'd, LS-unregistered LSUIElement binary reliably fails to
        // get a working notification-authorization prompt — doing it here
        // (vs. wrapping the launchd ProgramArguments in `open -j -a`) keeps
        // launchd's KeepAlive supervising the actual long-lived process.
        LSRegisterURL(Bundle.main.bundleURL as CFURL, true)

        UNUserNotificationCenter.current().delegate = self
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { [weak self] granted, _ in
            DispatchQueue.main.async {
                self?.controller.notificationsDenied = !granted
                self?.refreshNotificationStatus()
            }
        }

        controller = StatusItemController()
        controller.onTogglePause = { [weak self] in self?.handleTogglePause() }
        controller.onOpenNotificationSettings = { self.openNotificationSettings() }

        tailer = LogTailer(path: AgentPaths.publicLogPath) { [weak self] event, isBackfill in
            DispatchQueue.main.async { self?.handle(event: event, isBackfill: isBackfill) }
        }
        tailer.start()

        watchdogTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.runWatchdog()
        }

        refreshNotificationStatus()
    }

    private func handle(event: KillEvent, isBackfill: Bool) {
        switch event.type {
        case "heartbeat", "kill", "kill_child", "ambiguous_no_kill",
             "git_block", "git_scan_clean", "git_scan_ambiguous", "git_revert_failed":
            lastDaemonActivity = Date()
        case "state_change":
            lastDaemonActivity = Date()
            if event.reason == "paused" {
                controller.setState(.paused)
            } else if event.reason == "watching" {
                controller.setState(.watching)
            }
        default:
            break
        }

        guard event.type == "kill" || event.type == "git_block" else { return }
        controller.addEvent(event)

        guard !isBackfill, let display = IdentityFilter.present(event) else { return }
        postNotification(for: display, isGitBlock: event.type == "git_block")
    }

    private func runWatchdog() {
        if PauseToggle.isPaused {
            controller.setState(.paused)
            return
        }
        let threshold = heartbeatIntervalS * Double(unreachableAfterMissed)
        if Date().timeIntervalSince(lastDaemonActivity) > threshold {
            controller.setState(.unreachable)
        } else {
            controller.setState(.watching)
        }
    }

    private func handleTogglePause() {
        let wantsPaused = !PauseToggle.isPaused
        if let error = PauseToggle.setPaused(wantsPaused) {
            let alert = NSAlert()
            alert.messageText = wantsPaused ? "Couldn't pause" : "Couldn't resume"
            alert.informativeText = error
            alert.alertStyle = .warning
            alert.runModal()
            return
        }
        controller.setState(wantsPaused ? .paused : .watching)
    }

    private func refreshNotificationStatus() {
        UNUserNotificationCenter.current().getNotificationSettings { [weak self] settings in
            DispatchQueue.main.async {
                let denied = settings.authorizationStatus == .denied || settings.authorizationStatus == .notDetermined
                self?.controller.notificationsDenied = denied
                self?.controller.setState(self?.controller.state ?? .watching)  // force a menu rebuild to reflect it
            }
        }
    }

    private func openNotificationSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.notifications") {
            NSWorkspace.shared.open(url)
        }
    }

    private func postNotification(for display: DisplayEvent, isGitBlock: Bool = false) {
        let content = UNMutableNotificationContent()
        content.title = isGitBlock ? "Mabure reverted a suspicious git pull" : "Mabure killed a node -e process"
        content.body = display.title
        content.sound = .default
        let request = UNNotificationRequest(identifier: display.id, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request, withCompletionHandler: nil)
    }

    // Show the banner even though this is a background agent (there's no
    // foreground window for the system to otherwise suppress it for).
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }
}
