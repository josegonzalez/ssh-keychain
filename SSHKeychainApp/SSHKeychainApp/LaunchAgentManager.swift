import Foundation
import ServiceManagement
import SwiftUI

/// Wraps `SMAppService.agent(plistName:)` so the rest of the app can interact
/// with the launch agent through a Swift-friendly surface.
///
/// The agent plist lives at `Contents/Library/LaunchAgents/com.josegonzalez.ssh-keychain.plist`
/// inside the bundle. SMAppService keeps the registration database scoped to
/// the app's bundle identifier; macOS prompts the user once for approval (or
/// not at all if the user has already approved similar apps from the same
/// developer).
@MainActor
final class LaunchAgentManager: ObservableObject {
    static let plistName = "com.josegonzalez.ssh-keychain.plist"

    /// Mirror of `SMAppService.Status` mapped into a Swift enum we can switch
    /// on without dragging the framework type through views.
    enum State: Equatable {
        case notRegistered          // never been registered, or fully unregistered
        case enabled                // running
        case requiresApproval       // user denied or deferred the approval prompt
        case notFound               // launchd has no record (e.g. plist missing)
        case unknown(Int)           // SMAppService returns a new raw value we don't recognize yet
    }

    @Published private(set) var state: State = .notRegistered
    @Published private(set) var lastErrorMessage: String?

    private let service: SMAppService

    init() {
        self.service = SMAppService.agent(plistName: Self.plistName)
        refresh()
    }

    /// Re-reads the registration status from `SMAppService` and republishes it.
    func refresh() {
        state = map(service.status)
    }

    /// Registers (and starts) the launch agent. Triggers the macOS approval
    /// prompt the first time the user enables the agent for this bundle ID.
    func enable() {
        do {
            try service.register()
            lastErrorMessage = nil
        } catch {
            lastErrorMessage = "register failed: \(error.localizedDescription)"
        }
        refresh()
    }

    /// Unregisters the launch agent. Best-effort: macOS may keep an
    /// "approval required" remnant the next time we register.
    func disable() async {
        do {
            try await service.unregister()
            lastErrorMessage = nil
        } catch {
            lastErrorMessage = "unregister failed: \(error.localizedDescription)"
        }
        refresh()
    }

    /// Opens System Settings → Login Items at the right pane so the user can
    /// approve a denied registration. macOS doesn't expose a direct URL to
    /// our specific entry, but landing in the right pane is the standard UX.
    func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    private func map(_ status: SMAppService.Status) -> State {
        switch status {
        case .notRegistered: return .notRegistered
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notFound: return .notFound
        @unknown default: return .unknown(Int(status.rawValue))
        }
    }
}
