import AppKit

// Settings live in the app's defaults domain, e.g.
//   defaults write dev.drop-vet.app SSHHost myserver        (an alias from ~/.ssh/config)
//   defaults write dev.drop-vet.app RemoteRoot drop-vet     (relative to the remote home)
//   defaults write dev.drop-vet.app HistoryURL https://myserver.example:8750/
enum Settings {
    static var sshHost: String { UserDefaults.standard.string(forKey: "SSHHost") ?? "drop-vet" }
    static var remoteRoot: String { UserDefaults.standard.string(forKey: "RemoteRoot") ?? "drop-vet" }
    static var historyURL: URL? { UserDefaults.standard.string(forKey: "HistoryURL").flatMap(URL.init(string:)) }
}

final class DropView: NSView {
    let label = NSTextField(labelWithString: "Drop files\nhere")
    var busy = 0

    override init(frame: NSRect) {
        super.init(frame: frame)
        wantsLayer = true
        layer?.cornerRadius = 16
        layer?.backgroundColor = NSColor.windowBackgroundColor.withAlphaComponent(0.92).cgColor
        layer?.borderWidth = 2
        layer?.borderColor = NSColor.systemTeal.cgColor
        label.alignment = .center
        label.font = .systemFont(ofSize: 15, weight: .semibold)
        label.maximumNumberOfLines = 3
        label.translatesAutoresizingMaskIntoConstraints = false
        addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: centerXAnchor),
            label.centerYAnchor.constraint(equalTo: centerYAnchor),
            label.widthAnchor.constraint(lessThanOrEqualTo: widthAnchor, constant: -16),
        ])
        registerForDraggedTypes([.fileURL])
        toolTip = "Drop files to send · double-click or right-click for transfer history"
    }

    required init?(coder: NSCoder) { fatalError() }

    override var mouseDownCanMoveWindow: Bool { true }

    override func mouseUp(with event: NSEvent) {
        if event.clickCount == 2 { openHistory() }
    }

    override func menu(for event: NSEvent) -> NSMenu? {
        let m = NSMenu()
        m.addItem(withTitle: "Open Transfer History", action: #selector(openHistory), keyEquivalent: "").target = self
        m.addItem(withTitle: "Quit DropVet", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "")
        return m
    }

    @objc func openHistory() {
        if let url = Settings.historyURL { NSWorkspace.shared.open(url) } else { NSSound.beep() }
    }

    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
        layer?.backgroundColor = NSColor.systemTeal.withAlphaComponent(0.35).cgColor
        return .copy
    }

    override func draggingExited(_ sender: NSDraggingInfo?) { resetBackground() }

    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        resetBackground()
        let urls = sender.draggingPasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? []
        guard !urls.isEmpty else { return false }
        send(urls)
        return true
    }

    func resetBackground() {
        layer?.backgroundColor = NSColor.windowBackgroundColor.withAlphaComponent(0.92).cgColor
    }

    func send(_ urls: [URL]) {
        busy += 1
        label.stringValue = "Sending \(urls.count)…"
        DispatchQueue.global().async {
            // Upload into a dot-dir the intake ignores, then rename it into landing/ so the
            // intake only ever sees complete drops.
            let id = "\(Int(Date().timeIntervalSince1970))-\(UUID().uuidString.prefix(6))"
            // Host and root arrive as environment variables, never spliced into the script text.
            let script = """
            set -e
            o="-o BatchMode=yes -o ConnectTimeout=10"
            ssh $o "$DG_HOST" "mkdir -p '$DG_ROOT/landing/.part-$DG_ID'"
            scp -rq $o "$@" "$DG_HOST:$DG_ROOT/landing/.part-$DG_ID/"
            ssh $o "$DG_HOST" "mv '$DG_ROOT/landing/.part-$DG_ID' '$DG_ROOT/landing/drop-$DG_ID'"
            """
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/bin/sh")
            p.arguments = ["-c", script, "sh"] + urls.map(\.path)
            p.environment = ProcessInfo.processInfo.environment.merging(
                ["DG_HOST": Settings.sshHost, "DG_ROOT": Settings.remoteRoot, "DG_ID": id]) { $1 }
            let ok = (try? p.run()) != nil && { p.waitUntilExit(); return p.terminationStatus == 0 }()
            DispatchQueue.main.async {
                self.busy -= 1
                self.label.stringValue = ok ? "Sent \(urls.count) ✓\nscanning" : "Failed ✗\n(check ssh)"
                self.label.textColor = ok ? .systemGreen : .systemRed
                DispatchQueue.main.asyncAfter(deadline: .now() + 4) {
                    guard self.busy == 0 else { return }
                    self.label.stringValue = "Drop files\nhere"
                    self.label.textColor = .labelColor
                }
            }
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var panel: NSPanel!

    func applicationDidFinishLaunching(_ n: Notification) {
        let menu = NSMenu()
        let appItem = NSMenuItem()
        appItem.submenu = NSMenu()
        appItem.submenu?.addItem(withTitle: "Open Transfer History", action: #selector(AppDelegate.openHistory), keyEquivalent: "l").target = self
        appItem.submenu?.addItem(withTitle: "Quit DropVet", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(appItem)
        NSApp.mainMenu = menu

        let screen = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 800, height: 600)
        let size = NSSize(width: 150, height: 110)
        panel = NSPanel(contentRect: NSRect(x: screen.maxX - size.width - 24, y: screen.maxY - size.height - 24, width: size.width, height: size.height),
                        styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.level = .floating
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.isMovableByWindowBackground = true
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.setFrameAutosaveName("DropVetPanel")
        panel.contentView = DropView(frame: NSRect(origin: .zero, size: size))
        panel.orderFrontRegardless()
    }

    @objc func openHistory() {
        (panel.contentView as? DropView)?.openHistory()
    }

    func application(_ app: NSApplication, open urls: [URL]) {
        (panel.contentView as? DropView)?.send(urls)
    }

    func applicationShouldHandleReopen(_ app: NSApplication, hasVisibleWindows: Bool) -> Bool {
        panel.orderFrontRegardless()
        return true
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
