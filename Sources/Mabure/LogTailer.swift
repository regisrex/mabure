//
//  LogTailer.swift
//  Mabure (menu bar agent)
//
//  Tails the world-readable public event log (events.jsonl) live, handling
//  newsyslog rotation, and backfills recent history on startup so the
//  dropdown isn't empty right after the agent launches/relaunches.
//

import Foundation

final class LogTailer {
    typealias EventHandler = (KillEvent, _ isBackfill: Bool) -> Void

    private let path: String
    private let onEvent: EventHandler
    private var source: DispatchSourceFileSystemObject?
    private var fd: Int32 = -1
    private var readOffset: UInt64 = 0
    private let queue = DispatchQueue(label: "com.mabure.agent.logtail")

    init(path: String, onEvent: @escaping EventHandler) {
        self.path = path
        self.onEvent = onEvent
    }

    func start() {
        backfill(maxLines: 50)
        openAndWatch()
    }

    private func backfill(maxLines: Int) {
        guard let data = FileManager.default.contents(atPath: path) else { return }
        let text = String(decoding: data, as: UTF8.self)
        let lines = text.split(separator: "\n", omittingEmptySubsequences: true)
        for line in lines.suffix(maxLines) {
            if let event = decode(String(line)) {
                onEvent(event, true)
            }
        }
        readOffset = UInt64(data.count)
    }

    private func openAndWatch() {
        source?.cancel()
        if fd >= 0 { close(fd) }

        fd = open(path, O_EVTONLY)
        guard fd >= 0 else {
            // Log file doesn't exist yet (daemon not installed/started) —
            // retry shortly rather than treating this as fatal.
            queue.asyncAfter(deadline: .now() + 2) { [weak self] in self?.openAndWatch() }
            return
        }

        let src = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.extend, .write, .delete, .rename],
            queue: queue
        )
        src.setEventHandler { [weak self] in self?.handleFSEvent(src) }
        src.setCancelHandler { [weak self] in
            if let fd = self?.fd, fd >= 0 { close(fd) }
        }
        src.resume()
        source = src
    }

    private func handleFSEvent(_ src: DispatchSourceFileSystemObject) {
        let flags = src.data
        if flags.contains(.delete) || flags.contains(.rename) {
            // newsyslog rotated the file out from under us — reopen fresh.
            readOffset = 0
            openAndWatch()
            return
        }
        readNewLines()
    }

    private func readNewLines() {
        guard let handle = FileHandle(forReadingAtPath: path) else { return }
        defer { try? handle.close() }
        try? handle.seek(toOffset: readOffset)
        guard let data = try? handle.readToEnd(), !data.isEmpty else { return }
        readOffset += UInt64(data.count)

        let text = String(decoding: data, as: UTF8.self)
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if let event = decode(String(line)) {
                onEvent(event, false)
            }
        }
    }

    private func decode(_ line: String) -> KillEvent? {
        guard let data = line.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(KillEvent.self, from: data)
    }
}
