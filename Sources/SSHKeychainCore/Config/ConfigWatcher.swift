import Dispatch
import Foundation

/// Watches a single config file via `DispatchSource.makeFileSystemObjectSource`.
///
/// Fires `onChange` for `.write`, `.rename`, and `.attrib` events. Atomic
/// writes (which `ConfigStore.save` performs) typically arrive as `.rename`
/// + a fresh inode; we re-open the file descriptor on each event so we don't
/// chase the stale inode.
public final class ConfigWatcher: @unchecked Sendable {
    public let url: URL
    private let queue: DispatchQueue
    private let onChange: @Sendable (Config) -> Void
    private let onError: @Sendable (Error) -> Void
    private var currentSource: DispatchSourceFileSystemObject?
    private var currentFD: Int32 = -1

    public init(
        url: URL,
        queue: DispatchQueue = DispatchQueue(label: "ssh-keychain.config.watch"),
        onChange: @escaping @Sendable (Config) -> Void,
        onError: @escaping @Sendable (Error) -> Void = { _ in }
    ) {
        self.url = url
        self.queue = queue
        self.onChange = onChange
        self.onError = onError
    }

    public func start() {
        openAndWatch()
    }

    public func stop() {
        currentSource?.cancel()
        currentSource = nil
        if currentFD >= 0 {
            close(currentFD)
            currentFD = -1
        }
    }

    private func openAndWatch() {
        if currentFD >= 0 {
            close(currentFD)
            currentFD = -1
        }
        guard let fd = openWatched(url: url) else {
            // File doesn't exist yet - poll for it appearing.
            queue.asyncAfter(deadline: .now() + 1.0) { [weak self] in
                self?.openAndWatch()
            }
            return
        }
        currentFD = fd
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .rename, .attrib, .delete],
            queue: queue
        )
        source.setEventHandler { [weak self] in
            self?.handleEvent()
        }
        source.setCancelHandler { [fd] in
            close(fd)
        }
        source.resume()
        currentSource = source

        // Emit initial state.
        deliver()
    }

    private func handleEvent() {
        // Atomic rename invalidates the fd; re-open to follow the new inode.
        currentSource?.cancel()
        currentSource = nil
        currentFD = -1
        deliver()
        openAndWatch()
    }

    private func deliver() {
        do {
            let config = try ConfigStore.load(from: url)
            onChange(config)
        } catch {
            onError(error)
        }
    }

    private func openWatched(url: URL) -> Int32? {
        let fd = open(url.path, O_EVTONLY)
        return fd >= 0 ? fd : nil
    }
}
