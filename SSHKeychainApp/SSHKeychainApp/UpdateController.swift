import Combine
import Sparkle
import SwiftUI

/// Wraps Sparkle's `SPUStandardUpdaterController` and exposes a SwiftUI button
/// that can be dropped into the `Help` / `App` command group.
///
/// The controller is constructed once at app launch. Sparkle reads its config
/// (feed URL, EdDSA public key, schedule) from the app's Info.plist; we don't
/// pass any of that programmatically.
@MainActor
final class UpdateController: ObservableObject {
    @Published var canCheckForUpdates: Bool = false

    let standardController: SPUStandardUpdaterController
    private var cancellables = Set<AnyCancellable>()

    init() {
        // `startingUpdater: true` kicks off background checks per the
        // `SUScheduledCheckInterval` in Info.plist.
        self.standardController = SPUStandardUpdaterController(
            startingUpdater: true,
            updaterDelegate: nil,
            userDriverDelegate: nil
        )

        // Publish `canCheckForUpdates` so the SwiftUI button can disable itself
        // while Sparkle is mid-check.
        standardController.updater
            .publisher(for: \.canCheckForUpdates)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] in self?.canCheckForUpdates = $0 }
            .store(in: &cancellables)
    }

    func checkForUpdates() {
        standardController.checkForUpdates(nil)
    }
}

/// SwiftUI button for the Help menu's "Check for Updates…" item. Wires
/// directly to `UpdateController` so the disabled state stays in sync with
/// `SPUUpdater.canCheckForUpdates`.
struct CheckForUpdatesMenuItem: View {
    @ObservedObject var controller: UpdateController

    var body: some View {
        Button("Check for Updates…") {
            controller.checkForUpdates()
        }
        .disabled(!controller.canCheckForUpdates)
    }
}
