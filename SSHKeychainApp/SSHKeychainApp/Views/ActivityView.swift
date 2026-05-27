import AppKit
import SSHKeychainCore
import SwiftUI

/// Standalone window that polls the daemon for recent sign events.
///
/// Backed by `DaemonXPC.recentActivity`. Polls at 2s while visible; stops
/// when the window goes away. Supports filtering by fingerprint substring
/// and CSV export.
struct ActivityView: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @State private var events: [ActivityEvent] = []
    @State private var filter: String = ""
    @State private var pollTask: Task<Void, Never>?

    private var filteredEvents: [ActivityEvent] {
        let trimmed = filter.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return events }
        let needle = trimmed.lowercased()
        return events.filter {
            $0.fingerprint.lowercased().contains(needle)
                || ($0.callingProcess ?? "").lowercased().contains(needle)
        }
    }

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Activity").font(.title2)
                Spacer()
                TextField("Filter…", text: $filter)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 220)
                Button("Export CSV…") { exportCSV() }
                    .disabled(events.isEmpty)
            }
            if filteredEvents.isEmpty {
                Text("No sign events yet.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(filteredEvents.map(IdentifiableEvent.init)) {
                    TableColumn("Time") { e in Text(format(e.event.timestamp)) }
                    TableColumn("Key fingerprint") { e in Text(e.event.fingerprint).font(.callout.monospaced()) }
                    TableColumn("Caller") { e in Text(e.event.callingProcess ?? "?") }
                    TableColumn("Sig bytes") { e in Text("\(e.event.signatureLength)") }
                }
            }
        }
        .padding()
        .frame(minWidth: 720, minHeight: 360)
        .onAppear {
            pollTask = Task { await poll() }
        }
        .onDisappear {
            pollTask?.cancel()
        }
    }

    private func poll() async {
        while !Task.isCancelled {
            let latest = await coordinator.client.recentActivity(limit: 256)
            await MainActor.run { self.events = latest.reversed() }
            try? await Task.sleep(for: .seconds(2))
        }
    }

    private func format(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .medium
        return formatter.string(from: date)
    }

    private func exportCSV() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "ssh-keychain-activity.csv"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        var lines = ["timestamp,fingerprint,caller,signature_bytes"]
        for e in events {
            let caller = (e.callingProcess ?? "").replacingOccurrences(of: ",", with: " ")
            lines.append("\(format(e.timestamp)),\(e.fingerprint),\(caller),\(e.signatureLength)")
        }
        try? lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
    }
}

private struct IdentifiableEvent: Identifiable {
    let event: ActivityEvent
    var id: String { "\(event.timestamp.timeIntervalSinceReferenceDate)-\(event.fingerprint)" }
}
