import Foundation
import SSHKeychainCore
import SwiftUI

/// Observable wrapper over the on-disk `Config.json`. Holds the current Config,
/// applies mutations from the UI, and writes them back atomically.
///
/// The daemon's `ConfigWatcher` picks up the new file and reloads sources.
/// Worst-case latency is one DispatchSource event tick (sub-second).
@MainActor
final class ConfigViewModel: ObservableObject {
    @Published var config: Config
    @Published var loadError: String?
    @Published var dirty: Bool = false

    let url: URL

    init(url: URL = Config.defaultPath) {
        self.url = url
        if FileManager.default.fileExists(atPath: url.path) {
            do {
                self.config = try ConfigStore.load(from: url)
            } catch {
                self.config = Config()
                self.loadError = String(describing: error)
            }
        } else {
            self.config = Config()
        }
    }

    func save() throws {
        try ConfigStore.save(config, to: url)
        dirty = false
    }

    func saveOrSurfaceError() {
        do {
            try save()
        } catch {
            loadError = "save failed: \(error)"
        }
    }

    // MARK: backends

    func addBackend(name: String, config backendConfig: BackendConfig) {
        config.backends[name] = backendConfig
        dirty = true
        saveOrSurfaceError()
    }

    func removeBackend(name: String) {
        config.backends.removeValue(forKey: name)
        // Cascade: remove any sources that reference this backend.
        config.sources.removeAll { $0.backend == name }
        dirty = true
        saveOrSurfaceError()
    }

    func updateBackend(name: String, config backendConfig: BackendConfig) {
        config.backends[name] = backendConfig
        dirty = true
        saveOrSurfaceError()
    }

    // MARK: sources

    func addSource(_ entry: SourceEntry) {
        config.sources.append(entry)
        dirty = true
        saveOrSurfaceError()
    }

    func removeSource(at offsets: IndexSet) {
        config.sources.remove(atOffsets: offsets)
        dirty = true
        saveOrSurfaceError()
    }

    func moveSource(from source: IndexSet, to destination: Int) {
        config.sources.move(fromOffsets: source, toOffset: destination)
        dirty = true
        saveOrSurfaceError()
    }
}
