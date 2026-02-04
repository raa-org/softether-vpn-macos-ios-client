import Cocoa
import AppAuth

class AppDelegate: NSObject, NSApplicationDelegate {
    
    static var currentAuthorizationFlow: OIDExternalUserAgentSession?
    private var statusBarController: StatusBarController?
    
    let appGroupID: String = {
        guard let value = Bundle.main.object(forInfoDictionaryKey: "APP_GROUP_ID") as? String, !value.isEmpty else {
            preconditionFailure("Missing or empty APP_GROUP_ID in Info.plist. Provide a valid App Group identifier.")
        }
        return value
    }()


    func application(_ application: NSApplication, open urls: [URL]) {
        
            guard let url = urls.first else {
                return
            }
        
            if let flow = AppDelegate.currentAuthorizationFlow,
               flow.resumeExternalUserAgentFlow(with: url) {
                AppDelegate.currentAuthorizationFlow = nil
                return
            }
        }
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Initialize shared file logging (App Group if configured in Capabilities)
        LoggerService.configureHostApp(appGroupID: appGroupID)

        statusBarController = StatusBarController()
        
        VPNSystemExtensionManager.shared.activateIfNeeded()
        
        MainWindowController.shared.show()
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
    }
    
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        MainWindowController.shared.show()
        return true
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}
