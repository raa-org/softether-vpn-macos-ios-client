//
//  PublicIPViewModel.swift
//  SimpleTunnel
//

import Foundation

@MainActor
final class PublicIPViewModel: ObservableObject {
    @Published var ip: String = "Unknown"
    @Published var lastUpdated: Date? = nil
    @Published var errorText: String? = nil

    private let service = PublicIPService()
    private var task: Task<Void, Never>?
    private(set) var isActive = false

    func setActive(_ active: Bool, resetOnStop: Bool = true) {
        
        guard active != isActive else {
            return
        }
        isActive = active

        if active {
            start()
        } else {
            stop()
            if resetOnStop {
                ip = "Unknown"
                lastUpdated = nil
                errorText = nil
            }
        }
    }

    private func start() {
        guard task == nil else {
            return
        }

        task = Task { [weak self] in
            guard let self else {
                return
            }

            await self.refresh(force: true)

            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 60 * 1_000_000_000)
                await self.refresh(force: false)
            }
        }
    }

    private func stop() {
        task?.cancel()
        task = nil
    }

    private func refresh(force: Bool) async {
        do {
            let newIP = try await service.fetch(force: force)
            ip = newIP
            lastUpdated = Date()
            errorText = nil
        } catch is CancellationError {
            // rate-limit / cancel — ignore
        } catch {
            errorText = error.localizedDescription
        }
    }
}
