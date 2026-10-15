import AppKit
import Foundation
import Darwin
import CryptoKit

// No network entitlement. Only the user-selected source directory is read.
// Credentials and subscription URLs are never written to the output or logs.
// getpwuid returns the real user home; NSHomeDirectory is container-relative.
let realHome = URL(fileURLWithPath: String(cString: getpwuid(getuid())!.pointee.pw_dir), isDirectory: true)
let outputDirectory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("ShadowrocketRoutingSync", isDirectory: true)
let output = outputDirectory.appendingPathComponent("snapshot.json")
let authorizedSourceDirectory = realHome.appendingPathComponent("Library/Group Containers/group.com.liguangming.Shadowrocket", isDirectory: true)
let allowedTypes: Set<String> = ["Trojan", "VLESS", "Hysteria2", "Shadowsocks", "Socks5"]

enum SyncError: Error { case invalid(String) }

func readJSON(_ url: URL) throws -> Any {
    let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
    guard values.isRegularFile == true, values.isSymbolicLink != true,
          (values.fileSize ?? 0) <= 8_000_000 else { throw SyncError.invalid("文件类型或大小不符合要求") }
    return try decodeModel(Data(contentsOf: url))
}

func decodeModel(_ data: Data) throws -> Any {
    if let value = try? JSONSerialization.jsonObject(with: data) { return value }
    let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
    // Normalize UID references as CF$UID dictionaries. No archived classes are
    // instantiated: this only decodes bounded primitive containers and strings.
    let xml = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    // Foundation otherwise recreates its opaque UID objects from CF$UID keys.
    // Rename only XML key tags; escaped string contents are unaffected.
    let marker = "__shadowrocket_guard_uid_ref_7f1a"
    guard let xmlText = String(data: xml, encoding: .utf8) else { throw SyncError.invalid("档案编码异常") }
    let normalized = Data(xmlText.replacingOccurrences(of: "<key>CF$UID</key>", with: "<key>" + marker + "</key>").utf8)
    guard let archive = try PropertyListSerialization.propertyList(from: normalized, format: nil) as? [String: Any],
          archive["$archiver"] as? String == "NSKeyedArchiver",
          let objects = archive["$objects"] as? [Any], objects.count <= 100_000,
          let top = archive["$top"] as? [String: Any] else { throw SyncError.invalid("节点档案格式未确认") }
    var decodeSteps = 0
    func decode(_ value: Any, depth: Int, ancestors: Set<Int>) throws -> Any {
        decodeSteps += 1
        guard depth < 40, decodeSteps < 200_000 else { throw SyncError.invalid("节点档案层级或引用数量异常") }
        if let fields = value as? [String: Any] {
            if let ref = fields[marker] as? NSNumber, fields.count == 1 {
                let index = ref.intValue
                guard objects.indices.contains(index), !ancestors.contains(index) else { throw SyncError.invalid("节点档案引用异常") }
                if index == 0 { return NSNull() }
                return try decode(objects[index], depth: depth + 1, ancestors: ancestors.union([index]))
            }
            if let string = fields["NS.string"] { return try decode(string, depth: depth + 1, ancestors: ancestors) }
            if let values = fields["NS.objects"] as? [Any] {
                let items = try values.map { try decode($0, depth: depth + 1, ancestors: ancestors) }
                if let keys = fields["NS.keys"] as? [Any], keys.count == values.count {
                    let labels = try keys.map { try decode($0, depth: depth + 1, ancestors: ancestors) }
                    var result: [String: Any] = [:]
                    for (key, item) in zip(labels, items) {
                        guard let key = key as? String else { throw SyncError.invalid("节点档案字典键异常") }
                        result[key] = item
                    }
                    return result
                }
                return items
            }
            var result: [String: Any] = [:]
            for (key, item) in fields where key != "$class" { result[key] = try decode(item, depth: depth + 1, ancestors: ancestors) }
            return result
        }
        if let values = value as? [Any] { return try values.map { try decode($0, depth: depth + 1, ancestors: ancestors) } }
        return value
    }
    return try decode(top["root"] ?? top["NSKeyedArchiveRootObjectKey"] ?? top, depth: 0, ancestors: [])
}

func rowsIn(_ value: Any) -> [[String: Any]] {
    var result: [[String: Any]] = []
    func visit(_ item: Any, path: [String], depth: Int) {
        if depth > 20 { return }
        if let fields = item as? [String: Any] {
            if fields["type"] != nil, fields["host"] != nil {
                var row = fields; row["__guard_path"] = path.joined(separator: "/"); result.append(row)
            }
            for (key, child) in fields { visit(child, path: path + [key], depth: depth + 1) }
        } else if let values = item as? [Any] {
            for child in values { visit(child, path: path, depth: depth + 1) }
        }
    }
    visit(value, path: [], depth: 0)
    return result
}

func endpoint(_ row: [String: Any], subscription: String) throws -> [String: String]? {
    guard let kind = row["type"] as? String else { throw SyncError.invalid("节点协议字段类型未确认") }
    if kind == "Subscribe" { return nil }
    guard allowedTypes.contains(kind) else { throw SyncError.invalid("发现尚未支持的节点协议") }
    guard let host = row["host"] as? String, !host.isEmpty,
          host.range(of: "^[A-Za-z0-9.:-]{1,253}$", options: .regularExpression) != nil,
          !host.contains("://") else { throw SyncError.invalid("节点地址格式不符合要求") }
    let port = (row["port"] as? String) ?? (row["port"] as? NSNumber)?.stringValue ?? ""
    guard port.range(of: "^[0-9]{1,5}(-[0-9]{1,5})?$", options: .regularExpression) != nil else {
        throw SyncError.invalid("节点端口格式不符合要求")
    }
    let bounds = port.split(separator: "-").compactMap { Int($0) }
    guard !bounds.isEmpty, bounds.allSatisfy({ (1...65535).contains($0) }), bounds == bounds.sorted() else {
        throw SyncError.invalid("节点端口范围不符合要求")
    }
    let name = kind + " " + host + ":" + port
    guard name.count <= 512, !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
        throw SyncError.invalid("节点名称格式不符合要求")
    }
    return ["subscription": subscription, "name": name, "host": host, "port": port, "type": kind]
}

func collect(_ folder: URL) throws -> [String: Any] {
    let keys: [URLResourceKey] = [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey]
    guard let iterator = FileManager.default.enumerator(at: folder, includingPropertiesForKeys: keys,
                                                       options: [.skipsHiddenFiles]) else {
        throw SyncError.invalid("无法读取已授权目录")
    }
    var files: [URL] = []
    var inspected = 0
    for case let file as URL in iterator {
        inspected += 1
        guard inspected <= 3000 else { throw SyncError.invalid("目录项目过多，拒绝扩大读取范围") }
        let values = try file.resourceValues(forKeys: Set(keys))
        let depth = file.pathComponents.count - folder.pathComponents.count
        if values.isSymbolicLink == true || depth > 3 {
            iterator.skipDescendants(); continue
        }
        if values.isDirectory == true { continue }
        let name = file.lastPathComponent.lowercased()
        if name.contains("log") || name.hasSuffix(".conf") || name.hasSuffix(".js") { continue }
        if values.isRegularFile == true, (values.fileSize ?? 0) <= 8_000_000,
           (["model", "json", "data", "subscribe"].contains(file.pathExtension.lowercased())
             || file.lastPathComponent == "ServerManager") {
            files.append(file)
        }
    }
    // Prefer the current authoritative flat archive; do not mix removed nodes
    // from an older model cache into a new snapshot. A partial current archive
    // must fail closed instead of silently falling back to the older format.
    let primary = files.filter { $0.lastPathComponent == "ServerManager" }
    if !primary.isEmpty { files = primary }
    guard files.count <= 200 else { throw SyncError.invalid("候选节点文件过多") }
    var parsed: [(URL, [[String: Any]])] = []
    for file in files {
        do {
            let rows = rowsIn(try readJSON(file))
            if !rows.isEmpty { parsed.append((file, rows)) }
        } catch {
            // No arbitrary keys, source values, URLs or credentials in output.
            // An unreadable authoritative archive cannot become a ready source.
            continue
        }
    }
    var subscriptions: [(String, String, String)] = []
    for (file, rows) in parsed where ["shadowrocket.v2.model", "ServerManager"].contains(file.lastPathComponent) {
        for row in rows where row["type"] as? String == "Subscribe" {
            let label = "subscription-" + SHA256.hash(data: Data((row["uuid"] as? String ?? "").utf8)).prefix(8).map { String(format: "%02x", $0) }.joined()
            let identifier = row["uuid"] as? String ?? ""
            guard !label.isEmpty, UUID(uuidString: identifier) != nil else {
                throw SyncError.invalid("订阅标识结构尚未确认")
            }
            subscriptions.append((identifier.lowercased(), label, row["host"] as? String ?? ""))
        }
    }
    var records: [[String: String]] = []
    var matched: Set<String> = []
    for (file, rows) in parsed {
        let nodeRows = rows.filter { $0["type"] as? String != "Subscribe" }
        if nodeRows.isEmpty { continue }
        for row in nodeRows {
            let path = (file.path + "/" + (row["__guard_path"] as? String ?? "")).lowercased()
            let owners = subscriptions.filter { subscription in
                if path.contains(subscription.0) { return true }
                return ["data", "file"].contains { key in
                    guard let value = row[key] as? String, !value.isEmpty else { return false }
                    return value.lowercased() == subscription.0 || value == subscription.2
                }
            }
            let group: String
            if owners.count == 1 {
                group = owners[0].1; matched.insert(owners[0].0)
            } else if ["shadowrocket.v2.model", "ServerManager"].contains(file.lastPathComponent) {
                group = "本地节点"
            } else { continue }
            if let value = try endpoint(row, subscription: group) { records.append(value) }
        }
    }
    let missing = Set(subscriptions.map { $0.0 }).subtracting(matched)
    let mainDecoded = parsed.contains { ["shadowrocket.v2.model", "ServerManager"].contains($0.0.lastPathComponent) }
    let ready = mainDecoded && !records.isEmpty && missing.isEmpty
    var snapshot: [String: Any] = ["version": 1, "status": ready ? "ready" : "schema_unconfirmed",
            "observed_at": ISO8601DateFormatter().string(from: Date()),
            "source": "user-authorized Shadowrocket directory; read-only",
            "records": ready ? records : [], "subscription_count": subscriptions.count,
            "unmatched_subscription_count": missing.count, "source_directory": folder.path]
    if !ready {
        snapshot["candidate_files"] = files.count
        snapshot["decoded_files"] = parsed.count
    }
    return snapshot
}

func isAuthorizedSourceDirectory(_ url: URL) -> Bool {
    url.standardizedFileURL.path == authorizedSourceDirectory.standardizedFileURL.path
}

func writeSnapshot(_ value: [String: Any]) throws {
    try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: outputDirectory.path)
    let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    try data.write(to: output, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: output.path)
}

class AppDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow?
    private var status: NSTextField?
    private var wantsWindow = !CommandLine.arguments.contains("--background")
    var source: URL?
    var timer: Timer?
    var busy = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        createWindow()
        if let data = UserDefaults.standard.data(forKey: "sourceBookmark") {
            var stale = false
            if let url = try? URL(resolvingBookmarkData: data, options: [.withSecurityScope, .withoutUI],
                                  relativeTo: nil, bookmarkDataIsStale: &stale), isAuthorizedSourceDirectory(url),
               url.startAccessingSecurityScopedResource() {
                source = url
                if stale { try? remember(url) }
                refresh()
            }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in self?.refresh() }
        if wantsWindow { showWindow() }
    }

    private func createWindow() {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 600, height: 235),
                          styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        // AppKit's default close-time release conflicts with Swift ARC. Keep
        // the owned window alive for background refresh and Dock reopen events.
        window.isReleasedWhenClosed = false
        self.window = window
        window.title = "Shadowrocket 节点同步"
        window.center()
        let description = NSTextField(wrappingLabelWithString:
            "只读 Shadowrocket 的本地节点数据，输出服务器地址、端口和协议。\n不输出订阅链接、密码或密钥；本助手没有网络权限。\n来源不完整或读取失败时，防火墙保留原规则。")
        description.frame = NSRect(x: 24, y: 105, width: 552, height: 100)
        window.contentView!.addSubview(description)
        let status = NSTextField(wrappingLabelWithString: "等待精确节点目录的只读授权；本助手不修改防火墙规则。")
        self.status = status
        status.frame = NSRect(x: 24, y: 57, width: 552, height: 45)
        window.contentView!.addSubview(status)
        let button = NSButton(title: "授权只读节点目录…", target: self, action: #selector(choose))
        button.frame = NSRect(x: 24, y: 16, width: 225, height: 32)
        window.contentView!.addSubview(button)
    }

    // In-process AppKit component regression. Nothing is presented, no source
    // bookmark is read, and no vendor files or firewall snapshots are touched.
    func windowLifecycleSelfTest() throws {
        createWindow()
        weak var ownedWindow: NSWindow?
        ownedWindow = window
        for attempt in 1...8 {
            autoreleasepool { window?.close() }
            RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.02))
            guard ownedWindow != nil else { throw SyncError.invalid("关闭窗口后所有权丢失") }
            // Exercise the previously crashing retained-property getter, plus
            // the background status update that runs after the window closes.
            window?.title = "窗口生命周期测试 \(attempt)"
            status?.stringValue = "关闭后继续更新 \(attempt)"
            guard window?.title == "窗口生命周期测试 \(attempt)",
                  status?.stringValue == "关闭后继续更新 \(attempt)" else {
                throw SyncError.invalid("关闭后的窗口或后台状态不可访问")
            }
        }
        print("真实 AppKit 窗口关闭后八次所有权与后台状态更新检查通过。")
    }

    private func showWindow() {
        guard let window = window else { return }
        if window.isMiniaturized { window.deminiaturize(nil) }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func remember(_ url: URL) throws {
        let bookmark = try url.bookmarkData(options: [.withSecurityScope, .securityScopeAllowOnlyReadAccess],
                                           includingResourceValuesForKeys: nil, relativeTo: nil)
        UserDefaults.standard.set(bookmark, forKey: "sourceBookmark")
    }

    @objc func choose() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false; panel.canChooseDirectories = true; panel.allowsMultipleSelection = false
        panel.title = "授权只读 Shadowrocket 节点目录"
        panel.message = "选择 group.com.liguangming.Shadowrocket 共享目录。仅提取节点地址、端口和协议；不修改原文件。"
        panel.prompt = "授权只读"
        panel.directoryURL = authorizedSourceDirectory
        guard panel.runModal() == .OK, let url = panel.url else { return }
        guard isAuthorizedSourceDirectory(url) else {
            status?.stringValue = "请选择 group.com.liguangming.Shadowrocket 本身，不能选择上一级目录；原规则保持不变。"
            return
        }
        guard url.startAccessingSecurityScopedResource() else { status?.stringValue = "未获得只读授权，原规则不变。"; return }
        do {
            try remember(url)
            source?.stopAccessingSecurityScopedResource(); source = url; refresh()
        } catch { url.stopAccessingSecurityScopedResource(); status?.stringValue = "授权记录失败，原规则不变。" }
    }

    func refresh() {
        guard let source = source, !busy else { return }
        guard isAuthorizedSourceDirectory(source) else { return }
        busy = true
        DispatchQueue.global(qos: .utility).async {
            var message = "读取失败，保留防火墙原规则。"
            do {
                let value = try collect(source)
                try writeSnapshot(value)
                let count = (value["records"] as? [[String: String]])?.count ?? 0
                message = value["status"] as? String == "ready" ? "已读取 \(count) 个节点；防火墙同步由后台守护程序管理。" : "尚未确认完整节点格式；没有提交放行请求。"
            } catch {
                try? writeSnapshot(["version": 1, "status": "read_failed", "records": [],
                                    "observed_at": ISO8601DateFormatter().string(from: Date())])
            }
            DispatchQueue.main.async { self.status?.stringValue = message; self.busy = false }
        }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        wantsWindow = true
        showWindow()
        return true
    }
}

func selfTest() throws {
    func check(_ valid: Bool, _ label: String) throws {
        if !valid { throw SyncError.invalid(label) }
    }
    try check(isAuthorizedSourceDirectory(authorizedSourceDirectory), "已授权的精确目录被拒绝")
    try check(!isAuthorizedSourceDirectory(authorizedSourceDirectory.deletingLastPathComponent()), "接受了包含其他应用的父目录")
    try check(!isAuthorizedSourceDirectory(authorizedSourceDirectory.appendingPathComponent("child")), "接受了不完整子目录")
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    let identifier = "12345678-1234-1234-1234-123456789012"
    let main: [[String: Any]] = [
        ["type": "Subscribe", "uuid": identifier, "host": "https://example.org/sub?token=TEST_SECRET", "port": "0", "title": "机场测试"],
        ["type": "Socks5", "host": "192.0.2.10", "port": "18080", "password": "TEST_PASSWORD"]]
    let child: [[String: Any]] = [["type": "VLESS", "host": "198.51.100.20", "port": "24443", "title": "测试节点", "password": "TEST_UUID"]]
    try JSONSerialization.data(withJSONObject: main).write(to: folder.appendingPathComponent("shadowrocket.v2.model"))
    try JSONSerialization.data(withJSONObject: child).write(to: folder.appendingPathComponent(identifier + ".model"))
    let complete = try collect(folder)
    try check(complete["status"] as? String == "ready", "完整 JSON 来源未被识别")
    try check((complete["records"] as? [[String: String]])?.count == 2, "节点数量校验失败")
    let outputText = String(data: try JSONSerialization.data(withJSONObject: complete), encoding: .utf8)!
    try check(!outputText.contains("TEST_SECRET") && !outputText.contains("TEST_PASSWORD") && !outputText.contains("TEST_UUID"), "输出包含测试凭据")
    let archived = try NSKeyedArchiver.archivedData(withRootObject: ["servers": main, identifier: child], requiringSecureCoding: false)
    let decoded = try decodeModel(archived)
    try check(rowsIn(decoded).count == 3, "归档节点数量校验失败")
    try FileManager.default.removeItem(at: folder.appendingPathComponent(identifier + ".model"))
    let incomplete = try collect(folder)
    try check(incomplete["status"] as? String == "schema_unconfirmed", "不完整来源被接受")
    try check((incomplete["records"] as? [[String: String]])?.isEmpty == true, "不完整来源输出放行记录")
    // Actual ServerManager shape: a flat archive whose proxy records point to
    // the subscription URL in data. The URL must stay in memory only.
    try FileManager.default.removeItem(at: folder.appendingPathComponent("shadowrocket.v2.model"))
    var flatChild = child[0]; flatChild["data"] = "https://example.org/sub?token=TEST_SECRET"
    let flatArchive = try NSKeyedArchiver.archivedData(withRootObject: main + [flatChild], requiringSecureCoding: false)
    try flatArchive.write(to: folder.appendingPathComponent("ServerManager"))
    let flat = try collect(folder)
    try check(flat["status"] as? String == "ready", "真实档案结构未识别订阅归属")
    let flatText = String(data: try JSONSerialization.data(withJSONObject: flat), encoding: .utf8)!
    try check(!flatText.contains("TEST_SECRET") && !flatText.contains("TEST_PASSWORD") && !flatText.contains("TEST_UUID"), "归档输出包含测试凭据")
    let localOnly = try NSKeyedArchiver.archivedData(withRootObject: [main[1]], requiringSecureCoding: false)
    try localOnly.write(to: folder.appendingPathComponent("ServerManager"))
    let localSnapshot = try collect(folder)
    try check(localSnapshot["status"] as? String == "ready", "无订阅本地节点未识别")
    try check((localSnapshot["records"] as? [[String: String]])?.count == 1, "本地节点数量异常")
    for invalid in ["0", "65536", "443-1", "443;pass all"] {
        do { _ = try endpoint(["type": "VLESS", "host": "1.1.1.1", "port": invalid], subscription: "测试"); fatalError("Invalid port accepted") }
        catch SyncError.invalid { }
    }
    do { _ = try endpoint(["type": "VLESS", "host": "https://secret.invalid/token", "port": "443"], subscription: "测试"); fatalError("URL accepted") }
    catch SyncError.invalid { }
    print("只读节点解析、凭据排除、不完整来源与端口校验通过。")
}

if CommandLine.arguments.contains("--window-self-test") {
    let app = NSApplication.shared
    app.setActivationPolicy(.prohibited)
    do { try AppDelegate().windowLifecycleSelfTest(); exit(0) }
    catch SyncError.invalid(let reason) { print("窗口生命周期自检失败：" + reason); exit(1) }
    catch { print("窗口生命周期自检失败"); exit(1) }
}

if CommandLine.arguments.contains("--self-test") {
    do { try selfTest(); exit(0) }
    catch SyncError.invalid(let reason) { print("节点解析自检失败：" + reason); exit(1) }
    catch { print("节点解析自检失败"); exit(1) }
}

let delegate = AppDelegate()
let app = NSApplication.shared
app.setActivationPolicy(.regular)
app.delegate = delegate
// NSApplication's delegate reference is weak. Keep its owner (and the retained
// window) alive for the full event loop, including while the window is closed.
withExtendedLifetime(delegate) { app.run() }
