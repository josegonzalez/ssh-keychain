import ArgumentParser
import Dispatch
import Foundation
import SSHKeychainCore

struct AgentCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "agent",
        abstract: "Run the ssh-keychain agent."
    )

    @Option(name: .long, parsing: .singleValue,
            help: "Source spec: BACKEND:KEY[,KEY...|*]. Repeatable.")
    var source: [String] = []

    @Option(name: .long, help: "Unix socket path to bind. Defaults to ~/.ssh/ssh-keychain.sock.")
    var socket: String = "~/.ssh/ssh-keychain.sock"

    @Option(name: .long, help: "Time-to-live for cached unlocked signers (seconds). 0 disables caching.")
    var cacheTtl: Double = 0

    @Option(name: .long, help: "Max number of cached signers (LRU eviction).")
    var cacheMaxKeys: Int = 32

    @Flag(name: .long, help: "Short-lived agent mode: bind, fork the worker, parent exits 0 when socket is ready.")
    var once: Bool = false

    @Option(name: .long, help: "Idle timeout (seconds) for --once mode; child exits after this period with no live connections.")
    var idleTimeout: Double = 30

    @Option(name: .long, help: "Mach service name for the XPC control endpoint (consumed by `status`/`doctor` and the macOS app). When unset, no XPC listener is started.")
    var machService: String?

    /// Internal flag set by `OnceLauncher` when re-execing the actual worker.
    /// Hidden from --help output.
    @Flag(name: .customLong("__once-child"), help: .hidden)
    var onceChild: Bool = false

    func run() async throws {
        // Per the plan: if any --source is passed, it *replaces* config-file
        // sources entirely. If no --source given, the config file is required.
        let configFile = try loadConfigIfNeeded()

        if source.isEmpty && configFile == nil {
            throw ValidationError("at least one --source is required, or write a config file at \(Config.defaultPath.path)")
        }

        if once && !onceChild {
            // Parent process: spawn the worker and wait for it to bind the socket.
            let forwarded = buildForwardedArgs()
            let exec = CommandLine.arguments[0]
            let status = try OnceLauncher.spawnAndWait(
                executablePath: exec,
                forwardedArgs: forwarded,
                socketPath: effectiveSocket(config: configFile),
                readyTimeout: 5.0
            )
            throw ExitCode(status)
        }

        try await runWorker(isOnceWorker: onceChild, configFile: configFile)
    }

    /// Loads the user's config file. Returns nil if `--source` was given
    /// (CLI args override config entirely) or the file doesn't exist.
    private func loadConfigIfNeeded() throws -> Config? {
        if !source.isEmpty { return nil }
        let url = Config.defaultPath
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try ConfigStore.load(from: url)
    }

    private func effectiveSocket(config: Config?) -> String {
        // CLI flag always wins; otherwise take from config file.
        if socket != "~/.ssh/ssh-keychain.sock" { return socket }
        return config?.agent.socketPath ?? socket
    }

    private func runWorker(isOnceWorker: Bool, configFile: Config?) async throws {
        let registry = BackendRegistry()
        if let config = configFile {
            for (name, backendConfig) in config.backends {
                await registry.register(name: name, config: backendConfig)
            }
        }

        let specs: [SourceSpec]
        if !source.isEmpty {
            specs = try source.map { try SourceSpec.parse($0) }
        } else if let config = configFile {
            specs = try config.sources.map { try SourceSpec.parse("\($0.backend):\($0.key)") }
        } else {
            throw ValidationError("no sources to load")
        }

        let effectiveCacheTTL = source.isEmpty ? (configFile?.agent.cacheTTL ?? cacheTtl) : cacheTtl
        let effectiveCacheMax = source.isEmpty ? (configFile?.agent.cacheMaxKeys ?? cacheMaxKeys) : cacheMaxKeys
        let effectiveSocketPath = effectiveSocket(config: configFile)

        let service = AgentService(
            registry: registry,
            cacheTTL: effectiveCacheTTL,
            cacheMaxEntries: effectiveCacheMax
        )
        try await service.loadSources(specs)

        let server = AgentServer(socketPath: effectiveSocketPath, service: service)
        try await server.start()

        let banner = isOnceWorker
            ? "ssh-keychain --once worker listening on \(server.socketPath) (idle=\(idleTimeout)s)\n"
            : "ssh-keychain agent listening on \(server.socketPath)\n"
        FileHandle.standardError.write(Data(banner.utf8))

        installSignalHandlers(server: server, service: service)
        if isOnceWorker {
            server.enableIdleTimeout(idleTimeout)
        }

        // Config-driven daemon: watch the config file for changes and reload.
        if !isOnceWorker, source.isEmpty {
            startConfigWatcher(registry: registry, service: service)
        }

        // XPC control endpoint: when `--mach-service NAME` is given, expose
        // the DaemonXPC interface so `ssh-keychain status` / the app can
        // introspect the agent. Requires launchd to have created the Mach
        // service slot (which happens automatically when the agent is run
        // via the SMAppService-installed launchd plist).
        if let machService {
            let xpcService = DaemonXPCService(
                agent: service,
                socketPath: effectiveSocketPath,
                configPath: Config.defaultPath.path
            )
            let xpcServer = DaemonXPCServer(machServiceName: machService, service: xpcService)
            installedXPCServers.append(xpcServer)
            FileHandle.standardError.write(Data("ssh-keychain: XPC listener on Mach service \(machService)\n".utf8))
        }

        try await server.awaitShutdown()
    }

    private func startConfigWatcher(registry: BackendRegistry, service: AgentService) {
        let url = Config.defaultPath
        let watcher = ConfigWatcher(
            url: url,
            onChange: { newConfig in
                FileHandle.standardError.write(Data("ssh-keychain: config changed; reloading\n".utf8))
                Task {
                    for (name, backendConfig) in newConfig.backends {
                        await registry.register(name: name, config: backendConfig)
                    }
                    do {
                        let specs = try newConfig.sources.map {
                            try SourceSpec.parse("\($0.backend):\($0.key)")
                        }
                        try await service.replaceSources(specs)
                        FileHandle.standardError.write(Data("ssh-keychain: reload complete (\(specs.count) source specs)\n".utf8))
                    } catch {
                        FileHandle.standardError.write(Data("ssh-keychain: reload failed: \(error)\n".utf8))
                    }
                }
            },
            onError: { error in
                FileHandle.standardError.write(Data("ssh-keychain: config error: \(error)\n".utf8))
            }
        )
        watcher.start()
        configWatchers.append(watcher)
    }

    /// Build the args we forward to the once-worker. Mirrors our own flags but
    /// keeps the order stable for predictable child argv.
    private func buildForwardedArgs() -> [String] {
        var args = ["--socket=\(socket)", "--idle-timeout=\(idleTimeout)"]
        if cacheTtl != 0 { args.append("--cache-ttl=\(cacheTtl)") }
        if cacheMaxKeys != 32 { args.append("--cache-max-keys=\(cacheMaxKeys)") }
        for s in source {
            args.append("--source=\(s)")
        }
        return args
    }
}

/// Process-scoped registry of installed `ConfigWatcher`s. Same rationale as
/// `installedSignalSources`: must outlive the function that created them.
private nonisolated(unsafe) var configWatchers: [ConfigWatcher] = []

/// Same lifetime story for XPC listeners; once the function returns, the
/// listener would otherwise be deallocated and stop accepting connections.
private nonisolated(unsafe) var installedXPCServers: [DaemonXPCServer] = []

/// Process-scoped registry of installed `DispatchSourceSignal`s.
/// Need a long-lived owner; otherwise the sources are deallocated when
/// `installSignalHandlers` returns and stop firing.
private nonisolated(unsafe) var installedSignalSources: [DispatchSourceSignal] = []

/// Installs SIGINT/SIGTERM/SIGHUP/SIGUSR1 handlers on dedicated DispatchSources.
private func installSignalHandlers(server: AgentServer, service: AgentService) {
    let queue = DispatchQueue(label: "ssh-keychain.signals")

    func makeSource(_ sig: Int32, handler: @escaping @Sendable () -> Void) -> DispatchSourceSignal {
        let src = DispatchSource.makeSignalSource(signal: sig, queue: queue)
        src.setEventHandler(handler: handler)
        src.resume()
        return src
    }

    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    signal(SIGHUP, SIG_IGN)
    signal(SIGUSR1, SIG_IGN)

    let sigint = makeSource(SIGINT) {
        FileHandle.standardError.write(Data("ssh-keychain: SIGINT, shutting down\n".utf8))
        Task { try? await server.shutdown() }
    }
    let sigterm = makeSource(SIGTERM) {
        FileHandle.standardError.write(Data("ssh-keychain: SIGTERM, shutting down\n".utf8))
        Task { try? await server.shutdown() }
    }
    let sighup = makeSource(SIGHUP) {
        FileHandle.standardError.write(Data("ssh-keychain: SIGHUP, reloading sources\n".utf8))
        Task {
            do {
                try await service.reload()
                FileHandle.standardError.write(Data("ssh-keychain: reload complete\n".utf8))
            } catch {
                FileHandle.standardError.write(Data("ssh-keychain: reload failed: \(error)\n".utf8))
            }
        }
    }
    let sigusr1 = makeSource(SIGUSR1) {
        Task {
            let dump = await service.dumpState()
            FileHandle.standardError.write(Data(dump.utf8))
        }
    }

    installedSignalSources = [sigint, sigterm, sighup, sigusr1]
}
