//
//  main.swift
//  Mabure (menu bar agent)
//
//  Plain top-level entry point (not -parse-as-library) — see plan §6.
//  .accessory activation policy = no Dock icon, no app switcher entry,
//  just the status bar item (belt-and-suspenders alongside Info.plist's
//  LSUIElement).
//

import AppKit

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
