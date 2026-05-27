import Foundation
import SSHKeychainCore
import SwiftUI

/// Top-level state holder for the app. Owns the `DaemonXPCClient` (phase 22
/// fills in polling/reconciliation), tracks daemon status, and surfaces enough
/// to the views to render the menu and Settings panes.
@MainActor
final class AppCoordinator: ObservableObject {
    /// Bundle-identifier-based default; matches what the launch agent plist
    /// registers via `MachServices`. Overridable via debug builds.
    static let defaultMachService = "com.josegonzalez.ssh-keychain.daemon"

    @Published var daemonStatus: DaemonStatus?
    @Published var daemonReachable: Bool = false
    @Published var lastError: String?
    @Published var pollIntervalSeconds: Double = 2.0

    let configVM = ConfigViewModel()
    let launchAgent = LaunchAgentManager()

    /// Surfaced as a flag on `MenuBarContent` so users can re-open the wizard.
    @Published var showOnboarding: Bool = false

    /// Tracks whether the user has completed onboarding once; persisted in
    /// `UserDefaults` so we don't badger them again on every launch.
    @AppStorage("ssh-keychain.onboardingComplete") var onboardingComplete: Bool = false

    private(set) lazy var client: DaemonXPCClient = {
        DaemonXPCClient(endpoint: .machService(Self.defaultMachService))
    }()

    private var pollTask: Task<Void, Never>?
    private var backoff: Double = 0.5    // grows up to 30s on repeated misses

    init() {
        startPolling()
        if !onboardingComplete && configVM.config.backends.isEmpty {
            // Defer to next runloop so the @StateObject finishes wiring up
            // before any window tries to consume the change.
            DispatchQueue.main.async { [weak self] in
                self?.showOnboarding = true
            }
        }
    }

    deinit {
        pollTask?.cancel()
    }

    var menuBarIconName: String {
        // "key.fill" when daemon is reachable + running; "key.slash" otherwise.
        // The launch agent state takes priority: if approval is pending, we
        // surface that as the dot-circle icon so it's visually distinct from
        // "daemon crashed" or "not yet started".
        if launchAgent.state == .requiresApproval { return "exclamationmark.triangle.fill" }
        guard daemonReachable, let status = daemonStatus, status.running else { return "key.slash" }
        return "key.fill"
    }

    /// Recurring status poll with exponential backoff while the daemon is
    /// unreachable. Steady-state poll interval is `pollIntervalSeconds`.
    func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let status = await self.client.status()
                await self.applyPoll(status: status)
                let waitFor: Double = await MainActor.run {
                    if self.daemonReachable {
                        self.backoff = 0.5
                        return self.pollIntervalSeconds
                    } else {
                        let next = min(30.0, self.backoff * 1.5)
                        self.backoff = next
                        return next
                    }
                }
                try? await Task.sleep(for: .seconds(waitFor))
            }
        }
    }

    private func applyPoll(status: DaemonStatus?) async {
        await MainActor.run {
            self.daemonStatus = status
            self.daemonReachable = (status != nil)
        }
    }

    func reload() {
        Task { [weak self] in
            guard let self else { return }
            do {
                try await self.client.reload()
            } catch {
                await MainActor.run { self.lastError = "reload failed: \(error)" }
            }
        }
    }

    func lockAll() {
        Task { [weak self] in
            _ = await self?.client.lockAll()
        }
    }
}
