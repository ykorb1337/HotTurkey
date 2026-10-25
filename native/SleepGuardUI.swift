// A recovery surface before/after device sleep. No credential is persisted.
import AppKit

final class RecoveryPanel:NSPanel {
    override var canBecomeKey:Bool { true }
    override var canBecomeMain:Bool { true }
}
final class RecoveryField:NSSecureTextField {
    override func performKeyEquivalent(with event:NSEvent)->Bool {
        if event.modifierFlags.contains(.command),!event.modifierFlags.contains(.option),!event.modifierFlags.contains(.control),let editor=currentEditor() as? NSTextView {
            if event.charactersIgnoringModifiers?.lowercased()=="v" { editor.paste(nil);return true }
            if event.charactersIgnoringModifiers?.lowercased()=="a" { editor.selectAll(nil);return true }
        }
        return super.performKeyEquivalent(with:event)
    }
}

final class SleepGuardUI:NSObject {
    private var panel:RecoveryPanel?
    private var field:NSSecureTextField?
    private var label:NSTextField?
    private var feedback:NSTextField?
    private var timer:Timer?
    private var state:[String:Any]?
    private var updated=Date.distantPast
    private var pending:String?
    private var otherScreens=[NSWindow]()
    private var endLabel:NSTextField?
    private var screenObserver:NSObjectProtocol?

    override init() {
        super.init()
        screenObserver=NotificationCenter.default.addObserver(forName:NSApplication.didChangeScreenParametersNotification,object:nil,queue:.main) { [weak self] _ in
            guard let self,let value=self.state else { return }
            let stamp=self.updated;self.dismiss();self.render(value,recovery:nil);self.updated=stamp
        }
    }
    deinit { if let observer=screenObserver { NotificationCenter.default.removeObserver(observer) } }

    func takeWord()->String? { let value=pending;pending=nil;return value }
    @objc private func submit() {
        guard let value=field?.stringValue,!value.isEmpty else { return }
        guard value.unicodeScalars.count<=256 else { feedback?.stringValue="安全词最多 256 个字符";return }
        pending=value;field?.stringValue="";feedback?.stringValue="正在验证安全词…"
    }
    func render(_ value:Any?,recovery:Any?) {
        if let result=recovery as? [String:Any],let message=result["error"] as? String { feedback?.stringValue=message }
        guard let state=value as? [String:Any],let until=state["until"] as? Double,until>Date().timeIntervalSince1970 else { dismiss();return }
        self.state=state;updated=Date()
        if panel==nil {
            let app=NSApplication.shared;app.setActivationPolicy(.accessory)
            let screen=NSScreen.main?.frame ?? NSRect(x:0,y:0,width:1200,height:800)
            let window=RecoveryPanel(contentRect:screen,styleMask:.borderless,backing:.buffered,defer:false)
            window.isReleasedWhenClosed=false
            window.level = .screenSaver;window.collectionBehavior=[.canJoinAllSpaces,.fullScreenAuxiliary]
            window.backgroundColor=NSColor.windowBackgroundColor;window.hidesOnDeactivate=false
            let stack=NSStackView();stack.orientation = .vertical;stack.spacing=18;stack.translatesAutoresizingMaskIntoConstraints=false
            let title=NSTextField(labelWithString:"HotTurkey · 强制休息");title.font = .boldSystemFont(ofSize:30)
            let explanation=NSTextField(wrappingLabelWithString:"限制结束前，唤醒或重新登录仍会受到设备限制。\n如需紧急使用，输入设置时记下的安全词，放行本次限制时段。")
            explanation.alignment = .center
            let countdown=NSTextField(labelWithString:"");countdown.font = .systemFont(ofSize:18)
            let ending=NSTextField(labelWithString:"")
            let input=RecoveryField();input.placeholderString="紧急安全词";input.target=self;input.action=#selector(submit)
            let button=NSButton(title:"紧急放行本次时段",target:self,action:#selector(submit))
            let message=NSTextField(labelWithString:"");message.textColor = .secondaryLabelColor
            for view in [title,explanation,ending,countdown,input,button,message] { stack.addArrangedSubview(view) }
            let content=window.contentView!;content.addSubview(stack)
            NSLayoutConstraint.activate([stack.centerXAnchor.constraint(equalTo:content.centerXAnchor),stack.centerYAnchor.constraint(equalTo:content.centerYAnchor),stack.widthAnchor.constraint(equalToConstant:560),input.widthAnchor.constraint(equalToConstant:360)])
            panel=window;field=input;label=countdown;feedback=message;endLabel=ending
            for display in NSScreen.screens where display.frame != screen {
                let cover=NSWindow(contentRect:display.frame,styleMask:.borderless,backing:.buffered,defer:false)
                cover.isReleasedWhenClosed=false
                cover.level = .screenSaver;cover.collectionBehavior=[.canJoinAllSpaces,.fullScreenAuxiliary];cover.backgroundColor = .windowBackgroundColor
                let note=NSTextField(labelWithString:"HotTurkey · 强制休息中，请在主屏幕输入安全词")
                note.translatesAutoresizingMaskIntoConstraints=false;cover.contentView!.addSubview(note)
                NSLayoutConstraint.activate([note.centerXAnchor.constraint(equalTo:cover.contentView!.centerXAnchor),note.centerYAnchor.constraint(equalTo:cover.contentView!.centerYAnchor)])
                cover.orderFrontRegardless();otherScreens.append(cover)
            }
            window.makeKeyAndOrderFront(nil);window.makeFirstResponder(input);app.activate(ignoringOtherApps:true)
            timer=Timer.scheduledTimer(withTimeInterval:0.25,repeats:true) { [weak self] _ in self?.tick() }
        }
        tick()
    }
    private func tick() {
        guard let state,let until=state["until"] as? Double else { return }
        // The overlay cannot itself strand the user if the authority is gone.
        guard Date().timeIntervalSince(updated)<=5,until>Date().timeIntervalSince1970 else { dismiss();return }
        let remaining=max(0,(state["grace_remaining"] as? Double ?? 0)-Date().timeIntervalSince(updated))
        let action=["sleep":"睡眠","lock":"锁屏","logout":"注销","shutdown":"关机"][state["action"] as? String ?? "sleep"] ?? "限制使用"
        let formatter=DateFormatter();formatter.dateStyle = .short;formatter.timeStyle = .short
        endLabel?.stringValue="自动恢复时间："+formatter.string(from:Date(timeIntervalSince1970:until))
        label?.stringValue=remaining>0 ? "约 \(Int(ceil(remaining))) 秒后\(action) · 可在此输入安全词" : "正在限制使用 · 安全词仍可放行本次时段"
    }
    private func dismiss() { timer?.invalidate();timer=nil;field?.stringValue="";panel?.close();otherScreens.forEach { $0.close() };otherScreens=[];panel=nil;field=nil;label=nil;feedback=nil;endLabel=nil;state=nil }
}
