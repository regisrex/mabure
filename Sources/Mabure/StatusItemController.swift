//
//  StatusItemController.swift
//  Mabure (menu bar agent)
//
//  NSStatusItem + dropdown menu: a bounded (last 50) history of kill events,
//  a pause/resume toggle, and a status line reflecting one of three states —
//  watching / paused / daemon-unreachable. The menu is small (<=~55 items)
//  so it's simplest and cheap enough to just rebuild wholesale on any change
//  rather than incrementally diffing it.
//

import AppKit

final class StatusItemController {
    enum State { case watching, paused, unreachable }

    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let menu = NSMenu()
    private var history: [DisplayEvent] = []  // most recent first
    private let maxHistory = 50
    private(set) var state: State = .watching
    var notificationsDenied = false

    /// Wired by AppDelegate: called when the user clicks Pause/Resume.
    var onTogglePause: (() -> Void)?
    /// Wired by AppDelegate: opens System Settings' notification pane.
    var onOpenNotificationSettings: (() -> Void)?

    init() {
        statusItem.menu = menu
        rebuild()
    }

    func setState(_ newState: State) {
        guard newState != state else { return }
        state = newState
        rebuild()
    }

    /// Adds a kill event to the bounded history. Non-kill event types (state
    /// changes, heartbeats, ambiguous-no-kill) don't get a dropdown row —
    /// only IdentityFilter.present(_:) accepts `type == "kill"`.
    func addEvent(_ event: KillEvent) {
        guard let display = IdentityFilter.present(event) else { return }
        history.insert(display, at: 0)
        if history.count > maxHistory { history.removeLast(history.count - maxHistory) }
        rebuild()
    }

    private func rebuild() {
        menu.removeAllItems()

        let headerText: String
        switch state {
        case .watching: headerText = "Mabure — watching for node -e"
        case .paused: headerText = "Mabure — paused"
        case .unreachable: headerText = "Mabure — daemon unreachable ⚠️"
        }
        let header = NSMenuItem(title: headerText, action: nil, keyEquivalent: "")
        header.isEnabled = false
        menu.addItem(header)

        let pauseItem = NSMenuItem(
            title: state == .paused ? "Resume" : "Pause",
            action: #selector(togglePause), keyEquivalent: ""
        )
        pauseItem.target = self
        menu.addItem(pauseItem)

        if notificationsDenied {
            let notifItem = NSMenuItem(
                title: "Notifications disabled — click to open Settings",
                action: #selector(openNotificationSettings), keyEquivalent: ""
            )
            notifItem.target = self
            menu.addItem(notifItem)
        }

        menu.addItem(.separator())

        if history.isEmpty {
            let empty = NSMenuItem(title: "No kills yet", action: nil, keyEquivalent: "")
            empty.isEnabled = false
            menu.addItem(empty)
        } else {
            for event in history {
                let item = NSMenuItem(title: event.title, action: event.isOwn ? #selector(showDetail(_:)) : nil, keyEquivalent: "")
                item.toolTip = event.subtitle
                if event.isOwn {
                    item.target = self
                    item.representedObject = event
                }
                menu.addItem(item)
                let sub = NSMenuItem(title: "    \(event.subtitle)", action: nil, keyEquivalent: "")
                sub.isEnabled = false
                menu.addItem(sub)
            }
        }

        menu.addItem(.separator())
        let quit = NSMenuItem(title: "Quit Mabure", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)

        updateIcon()
    }

    private func updateIcon() {
        // Custom alien-head glyphs (see Tools/generate-icons.swift) — a
        // consistent brand mark across states, recolored per state rather
        // than swapped for an unrelated shape. "watching" is a template
        // image (auto light/dark); the alert states are colored so they
        // stay legible/attention-grabbing regardless of menu bar tint.
        let name: String
        let isTemplate: Bool
        switch state {
        case .watching: name = "icon-watching"; isTemplate = true
        case .paused: name = "icon-paused"; isTemplate = false
        case .unreachable: name = "icon-unreachable"; isTemplate = false
        }
        // Loaded from the raw file (not NSImage(named:)'s @1x/@2x bundle
        // pairing, which proved fragile for loose Resources PNGs) and
        // explicitly pinned to the standard menu-bar glyph size — the
        // source file is a high-res master, so this always downsamples
        // cleanly regardless of display backing scale.
        let path = Bundle.main.path(forResource: name, ofType: "png")
        let image = path.flatMap { NSImage(contentsOfFile: $0) }
        image?.size = NSSize(width: 18, height: 18)
        image?.isTemplate = isTemplate
        statusItem.button?.image = image
    }

    @objc private func togglePause() { onTogglePause?() }
    @objc private func openNotificationSettings() { onOpenNotificationSettings?() }

    @objc private func showDetail(_ sender: NSMenuItem) {
        guard let event = sender.representedObject as? DisplayEvent, let detail = event.detail else { return }
        let alert = NSAlert()
        alert.messageText = event.title
        alert.informativeText = detail
        alert.alertStyle = .informational
        alert.runModal()
    }

    @objc private func quit() {
        NSApplication.shared.terminate(nil)
    }
}
