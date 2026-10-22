import AppKit
import WebKit
import UserNotifications

final class Delegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler, UNUserNotificationCenterDelegate {
    var window: NSWindow!
    var web: WKWebView!
    var status: NSStatusItem!
    var service: Process?
    var base: URL!
    var dataDirectory: URL!
    var notices: NSObjectProtocol?
    var retries = 0
    var loadingLabel: NSTextField!
    var navigationGeneration = 0
    var navigationRecoveries = 0
    var navigationRecoveryPending = false
    var navigationFinished = false
    var currentNavigation: WKNavigation?
    var installation: Process?
    var connectionPending = false
    let probeSession: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]
        return URLSession(configuration:config)
    }()
    func applicationDidFinishLaunching(_ notification: Notification) {
        let resources = Bundle.main.resourceURL!
        base = resources.appendingPathComponent("project")
        if let override = Bundle.main.object(forInfoDictionaryKey:"HotTurkeyDataDirectory") as? String {
            dataDirectory = URL(fileURLWithPath:override)
        } else {
            dataDirectory = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/HotTurkey")
        }
        try? FileManager.default.createDirectory(at:dataDirectory,withIntermediateDirectories:true)
        let menu = NSMenu()
        menu.addItem(withTitle:"打开 HotTurkey",action:#selector(show),keyEquivalent:"")
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle:"关闭窗口（后台继续）",action:#selector(hide),keyEquivalent:"")
        menu.addItem(withTitle:"退出界面（后台继续）",action:#selector(quit),keyEquivalent:"")
        status = NSStatusBar.system.statusItem(withLength:NSStatusItem.variableLength)
        status.button?.image = NSImage(systemSymbolName:"flame.fill",accessibilityDescription:"HotTurkey")
        status.menu = menu
        let config = WKWebViewConfiguration()
        config.userContentController.add(self,name:"native")
        web = WKWebView(frame:.zero,configuration:config)
        web.navigationDelegate = self
        web.uiDelegate = self
        window = NSWindow(contentRect:NSRect(x:0,y:0,width:1200,height:820),styleMask:[.titled,.closable,.miniaturizable,.resizable],backing:.buffered,defer:false)
        window.minSize = NSSize(width:920,height:650)
        window.title = "HotTurkey"
        window.contentView = web
        loadingLabel = NSTextField(labelWithString:"正在连接本地后台…")
        loadingLabel.font = NSFont.systemFont(ofSize:17)
        loadingLabel.textColor = .secondaryLabelColor
        loadingLabel.translatesAutoresizingMaskIntoConstraints = false
        web.addSubview(loadingLabel)
        NSLayoutConstraint.activate([loadingLabel.centerXAnchor.constraint(equalTo:web.centerXAnchor),loadingLabel.centerYAnchor.constraint(equalTo:web.centerYAnchor)])
        window.center()
        window.isReleasedWhenClosed = false
        UNUserNotificationCenter.current().delegate = self
        notices = DistributedNotificationCenter.default().addObserver(forName:NSNotification.Name("local.hotturkey.notice"),object:nil,queue:.main) { note in
            let content = UNMutableNotificationContent(); content.title = "HotTurkey"; content.body = note.object as? String ?? ""
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier:UUID().uuidString,content:content,trigger:nil))
        }
        connect()
        if !CommandLine.arguments.contains("--login") { show() }
    }
    func connection(_ completion:@escaping([String:Any]?)->Void) {
        guard let data = try? Data(contentsOf:dataDirectory.appendingPathComponent("connection.json")), let object = (try? JSONSerialization.jsonObject(with:data)) as? [String:Any], let port = object["port"] as? Int, let token = object["token"] as? String else { completion(nil); return }
        var request = URLRequest(url:URL(string:"http://127.0.0.1:\(port)/api/state")!,cachePolicy:.reloadIgnoringLocalCacheData,timeoutInterval:1)
        request.setValue("Bearer \(token)",forHTTPHeaderField:"Authorization")
        probeSession.dataTask(with:request) { _, response, error in
            let success = (response as? HTTPURLResponse)?.statusCode == 200
            DispatchQueue.main.async {
                if !success {
                    let failure = error as NSError?
                    self.desktopLog("probe failed status \((response as? HTTPURLResponse)?.statusCode ?? 0) error \(failure?.code ?? 0)")
                }
                completion(success ? object : nil)
            }
        }.resume()
    }
    func connect() {
        if connectionPending { return }
        connectionPending = true
        connection { object in
            self.connectionPending = false
            self.connected(object)
        }
    }
    func connected(_ object:[String:Any]?) {
        if let object, let port = object["port"] as? Int, let token = object["token"] as? String {
            retries = 0
            navigationGeneration += 1
            let generation = navigationGeneration
            navigationFinished = false
            loadingLabel.stringValue = "正在加载专注空间…"
            loadingLabel.isHidden = false
            currentNavigation = web.load(URLRequest(url:URL(string:"http://127.0.0.1:\(port)/#token=\(token)")!))
            desktopLog("loading")
            DispatchQueue.main.asyncAfter(deadline:.now()+4) {
                if generation == self.navigationGeneration && !self.navigationFinished { self.recoverNavigation("load deadline") }
            }
            return
        }
        if service?.isRunning == false { service = nil }
        let managed = FileManager.default.fileExists(atPath:FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents/local.hotturkey.service.plist").path) && Bundle.main.object(forInfoDictionaryKey:"HotTurkeyDataDirectory") == nil
        if service == nil && !managed {
            let process = Process()
            let configPath = Bundle.main.resourceURL!.appendingPathComponent("python-path.txt")
            let python = ((try? String(contentsOf:configPath,encoding:.utf8)) ?? "").trimmingCharacters(in:.whitespacesAndNewlines)
            if python.isEmpty { showError("应用运行时配置缺失，请重新安装 HotTurkey。"); return }
            process.executableURL = python.hasPrefix("/") ? URL(fileURLWithPath:python) : Bundle.main.resourceURL!.appendingPathComponent(python)
            process.currentDirectoryURL = base
            process.arguments = ["-E","-s","-B","-m","hotturkey.server","--enforce"]
            process.environment = ProcessInfo.processInfo.environment.merging(["HOTTURKEY_DATA":dataDirectory.path,"PYTHONDONTWRITEBYTECODE":"1"]) { _,new in new }
            do { try process.run(); service = process } catch { showError("无法启动后台：\(error)"); return }
        }
        retries += 1
        if retries > 30 { showError("后台连接失败。请查看 ~/Library/Application Support/HotTurkey/service.log"); return }
        DispatchQueue.main.asyncAfter(deadline:.now()+0.3) { self.connect() }
    }
    func desktopLog(_ message:String) {
        // Never log the navigation URL, which initially carries a local token.
        let path = dataDirectory.appendingPathComponent("desktop.log")
        let data = "\(Date().timeIntervalSince1970) \(message)\n".data(using:.utf8)!
        if let handle = try? FileHandle(forWritingTo:path) {
            handle.seekToEndOfFile(); handle.write(data); handle.closeFile()
        } else { FileManager.default.createFile(atPath:path.path,contents:data,attributes:[.posixPermissions:0o600]) }
    }
    func recoverNavigation(_ reason:String) {
        if navigationRecoveryPending { return }
        navigationGeneration += 1
        navigationRecoveries += 1
        desktopLog("recovering \(reason) attempt \(navigationRecoveries)")
        if navigationRecoveries > 3 {
            loadingLabel.stringValue = "界面连接失败，请从菜单栏重新打开 HotTurkey。"
            loadingLabel.isHidden = false
            return
        }
        navigationRecoveryPending = true
        DispatchQueue.main.asyncAfter(deadline:.now()+0.5) {
            self.navigationRecoveryPending = false
            self.connect()
        }
    }
    func showError(_ text:String) { let alert = NSAlert(); alert.messageText = text; alert.beginSheetModal(for:window) { _ in } }
    @objc func show() {
        NSApp.setActivationPolicy(.regular); window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps:true)
        if navigationRecoveries > 3 { navigationRecoveries = 0; connect() }
    }
    @objc func hide() { window.orderOut(nil) }
    @objc func quit() { NSApp.terminate(nil) }
    func applicationShouldHandleReopen(_ sender:NSApplication,hasVisibleWindows:Bool)->Bool { show(); return true }
    func userContentController(_ userContentController:WKUserContentController,didReceive message:WKScriptMessage) {
        guard message.frameInfo.isMainFrame, message.frameInfo.securityOrigin.host == "127.0.0.1" else { return }
        if let body = message.body as? [String:Any], body["op"] as? String == "install" {
            guard let data = try? Data(contentsOf:dataDirectory.appendingPathComponent("connection.json")),
                  let connection = (try? JSONSerialization.jsonObject(with:data)) as? [String:Any],
                  let port = connection["port"] as? Int,
                  message.frameInfo.securityOrigin.port == port else { return }
            if Bundle.main.object(forInfoDictionaryKey:"HotTurkeyDataDirectory") != nil {
                web.evaluateJavaScript("window.receiveInstallationResult({ok:false,message:'测试版不安装正式后台，请使用 HotTurkey 正式应用。'})")
                return
            }
            installBackend(body["extensionIDs"] as? [String] ?? [])
            return
        }
        if let body = message.body as? [String:Any], body["op"] as? String == "ready", CommandLine.arguments.contains("--login") {
            if body["tray"] as? Bool == true { NSApp.setActivationPolicy(.accessory) }
            else { show() }
            return
        }
        guard let command = message.body as? String else { return }
        if command == "reconnect" { connect(); return }
        if command == "notifications" { UNUserNotificationCenter.current().requestAuthorization(options:[.alert,.sound]) { _,_ in } }
        if command == "pickApp" || command == "pickFolder" || command == "pickBinary" {
            let panel = NSOpenPanel(); panel.canChooseDirectories = command == "pickFolder"; panel.canChooseFiles = command != "pickFolder"; panel.allowsMultipleSelection = true
            panel.beginSheetModal(for:window) { response in
                if response == .OK {
                    let values = panel.urls.map { url -> String in
                        if command == "pickFolder" { return "folder:"+url.path }
                        if command == "pickBinary" { return "binary:"+url.path }
                        if let id = Bundle(url:url)?.bundleIdentifier { return "bundle:"+id }
                        return url.path
                    }
                    if let data = try? JSONSerialization.data(withJSONObject:values), let json = String(data:data,encoding:.utf8) {
                        self.web.evaluateJavaScript("window.receiveApps(\(json))")
                    }
                }
            }
        }
    }
    func installBackend(_ identifiers:[String]) {
        if installation != nil { return }
        let config = Bundle.main.resourceURL!.appendingPathComponent("python-path.txt")
        let value = ((try? String(contentsOf:config,encoding:.utf8)) ?? "").trimmingCharacters(in:.whitespacesAndNewlines)
        let python = value.hasPrefix("/") ? URL(fileURLWithPath:value) : Bundle.main.resourceURL!.appendingPathComponent(value)
        let process = Process(); let output = Pipe()
        process.executableURL = python
        process.currentDirectoryURL = base
        process.arguments = ["-E","-s","-B",base.appendingPathComponent("scripts/install.py").path,"--app-source",Bundle.main.bundleURL.path]
        for identifier in identifiers { process.arguments! += ["--extension-id",identifier] }
        process.standardOutput = output; process.standardError = output
        installation = process
        do {
            try process.run()
            DispatchQueue.global(qos:.userInitiated).async {
                let data = output.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                let result:[String:Any] = ["ok":process.terminationStatus == 0,"message":String(data:data,encoding:.utf8) ?? "安装未返回结果"]
                DispatchQueue.main.async {
                    self.installation = nil
                    if let encoded = try? JSONSerialization.data(withJSONObject:result), let json = String(data:encoded,encoding:.utf8) {
                        self.web.evaluateJavaScript("window.receiveInstallationResult(\(json))")
                    }
                    if process.terminationStatus == 0 { self.connect() }
                }
            }
        } catch {
            installation = nil
            showError("无法启动安装：\(error.localizedDescription)")
            web.evaluateJavaScript("window.receiveInstallationResult({ok:false,message:'无法启动安装'})")
        }
    }
    func webView(_ webView:WKWebView,decidePolicyFor navigationAction:WKNavigationAction,decisionHandler:@escaping(WKNavigationActionPolicy)->Void) {
        if navigationAction.request.url?.absoluteString == "about:blank" { decisionHandler(.allow); return }
        if let url = navigationAction.request.url, url.host != "127.0.0.1" { NSWorkspace.shared.open(url); decisionHandler(.cancel) } else { decisionHandler(.allow) }
    }
    func webView(_ webView:WKWebView,didFinish navigation:WKNavigation!) {
        guard navigation === currentNavigation, webView.url?.host == "127.0.0.1" else { return }
        navigationFinished = true
        navigationRecoveries = 0
        loadingLabel.isHidden = true
        desktopLog("ready")
    }
    func webView(_ webView:WKWebView,didFailProvisionalNavigation navigation:WKNavigation!,withError error:Error) {
        navigationFailed(navigation,error)
    }
    func webView(_ webView:WKWebView,didFail navigation:WKNavigation!,withError error:Error) {
        navigationFailed(navigation,error)
    }
    func navigationFailed(_ navigation:WKNavigation?,_ error:Error) {
        if let navigation, let currentNavigation, navigation !== currentNavigation { return }
        let failure = error as NSError
        if failure.code == NSURLErrorCancelled { return }
        recoverNavigation("navigation error \(failure.domain) \(failure.code)")
    }
    func webViewWebContentProcessDidTerminate(_ webView:WKWebView) { recoverNavigation("web process terminated") }
    func webView(_ webView:WKWebView,runJavaScriptAlertPanelWithMessage message:String,initiatedByFrame frame:WKFrameInfo,completionHandler:@escaping()->Void) {
        guard frame.isMainFrame, frame.securityOrigin.host == "127.0.0.1" else { completionHandler(); return }
        let alert = NSAlert(); alert.messageText = message; alert.addButton(withTitle:"确定")
        alert.beginSheetModal(for:window) { _ in completionHandler() }
    }
    func webView(_ webView:WKWebView,runJavaScriptConfirmPanelWithMessage message:String,initiatedByFrame frame:WKFrameInfo,completionHandler:@escaping(Bool)->Void) {
        guard frame.isMainFrame, frame.securityOrigin.host == "127.0.0.1" else { completionHandler(false); return }
        let alert = NSAlert(); alert.messageText = message; alert.alertStyle = .warning
        alert.addButton(withTitle:"确定"); alert.addButton(withTitle:"取消")
        alert.beginSheetModal(for:window) { response in completionHandler(response == .alertFirstButtonReturn) }
    }
    func webView(_ webView:WKWebView,runJavaScriptTextInputPanelWithPrompt prompt:String,defaultText:String?,initiatedByFrame frame:WKFrameInfo,completionHandler:@escaping(String?)->Void) {
        guard frame.isMainFrame, frame.securityOrigin.host == "127.0.0.1" else { completionHandler(nil); return }
        let alert = NSAlert(); alert.messageText = prompt
        let input = NSTextField(frame:NSRect(x:0,y:0,width:320,height:24)); input.stringValue = defaultText ?? ""
        alert.accessoryView = input; alert.window.initialFirstResponder = input
        alert.addButton(withTitle:"确定"); alert.addButton(withTitle:"取消")
        alert.beginSheetModal(for:window) { response in completionHandler(response == .alertFirstButtonReturn ? input.stringValue : nil) }
    }
    func userNotificationCenter(_ center:UNUserNotificationCenter,willPresent notification:UNNotification,withCompletionHandler completionHandler:@escaping(UNNotificationPresentationOptions)->Void) { completionHandler([.banner,.sound]) }
}
let app = NSApplication.shared
let delegate = Delegate()
app.setActivationPolicy(.regular)
app.delegate = delegate
let menu = NSMenu(); let appItem = NSMenuItem(); menu.addItem(appItem)
let appMenu = NSMenu(); appItem.submenu = appMenu
appMenu.addItem(withTitle:"退出 HotTurkey 界面",action:#selector(NSApplication.terminate(_:)),keyEquivalent:"q")
let fileItem = NSMenuItem(); menu.addItem(fileItem); let fileMenu = NSMenu(title:"文件"); fileItem.submenu = fileMenu
fileMenu.addItem(withTitle:"关闭窗口",action:#selector(NSWindow.performClose(_:)),keyEquivalent:"w")
let editItem = NSMenuItem(); menu.addItem(editItem); let editMenu = NSMenu(title:"编辑"); editItem.submenu = editMenu
for (title,selector,key) in [("撤销","undo:","z"),("剪切","cut:","x"),("复制","copy:","c"),("粘贴","paste:","v"),("全选","selectAll:","a")] { editMenu.addItem(withTitle:title,action:Selector(selector),keyEquivalent:key) }
app.mainMenu = menu
app.run()
