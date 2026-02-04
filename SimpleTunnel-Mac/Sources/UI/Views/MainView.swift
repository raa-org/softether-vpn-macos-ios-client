//
//  MainView.swift
//  SimpleTunnel

import SwiftUI
import AppKit

struct MainView: View {
    
    @ObservedObject var viewModel: VPNViewModel
    @ObservedObject var publicIP: PublicIPViewModel
    @State private var isImportingConfig = false
    
    private static let logger = LoggerService.vpnapp
    
    var body: some View {
        
        let buttonWidth: CGFloat = 150
        
        VStack(spacing: 16) {
            
            Grid(alignment: .leading, horizontalSpacing: 8, verticalSpacing: 8) {
                
                vpnRow

                GridRow {
                    Text("State:")
                        .font(.headline)
                        .gridColumnAlignment(.leading)

                    HStack(spacing: 8) {
                        Circle()
                            .fill(indicatorColor(viewModel.statusIndicator))
                            .frame(width: 10, height: 10)
                            .animation(.default, value: viewModel.statusIndicator)

                        Text(viewModel.statusText)
                            .font(.headline)
                    }
                    .gridColumnAlignment(.leading)
                }

                GridRow {
                    Text("Public IP:")
                        .font(.body)
                        .gridColumnAlignment(.leading)

                    Text(publicIP.ip)
                        .font(.body)
                        .monospacedDigit()
                        .gridColumnAlignment(.leading)
                }
            }
            .fileImporter(isPresented: $isImportingConfig, allowedContentTypes: [.json], allowsMultipleSelection: false) { result in
                    guard case .success(let urls) = result,
                          let url = urls.first
                    else {
                        return
                    }

                    do {
                        try viewModel.importConfig(from: url)
                    } catch {
                        Self.logger.both(.error, "Import failed: \(error.localizedDescription)")
                    }
                }
            
            Spacer()
            
            Button(action: {
                Task { await viewModel.toggleTunnel() }
            }) {
                Text(viewModel.buttonTitle)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .frame(maxWidth: .infinity)
            }
            .frame(minWidth: buttonWidth, maxWidth: buttonWidth)
            .controlSize(.regular)
            .disabled(!viewModel.hasProfile || viewModel.isBusy)
            
            Button(action: {
                viewModel.logout()
            }) {
                Text("Logout")
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .frame(maxWidth: .infinity)
            }
            .frame(minWidth: buttonWidth, maxWidth: buttonWidth)
            .controlSize(.regular)
            .disabled(!viewModel.canLogout || viewModel.isBusy)
            
            Button(action: viewModel.showAppLogInFinder) {
                Text("Show Log")
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .frame(maxWidth: .infinity)
            }
            .frame(minWidth: buttonWidth, maxWidth: buttonWidth)
            .controlSize(.regular)
            .contextMenu {
                Button("Show only App Log") { viewModel.showAppLogInFinder() }
                Button("Export Diagnostics (.zip)") { viewModel.exportDiagnosticsZip() }
            }

            VStack(alignment: .trailing, spacing: 2) {
                    Text(AppInfo.hostVersionText)
                    Text(AppInfo.extensionVersionText)
                }
                .font(.footnote)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .trailing)
        }
        .padding(20)
        .frame(width: 386, height: 298)
        .onAppear {
            publicIP.setActive(viewModel.statusIndicator == .connected)
        }
        .onChange(of: viewModel.statusIndicator) { newValue in
            publicIP.setActive(newValue == .connected)
        }
        .overlay(alignment: .topTrailing) {
            if let t = viewModel.toast {
                ToastView(kind: t.kind, text: t.text)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topTrailing)
                    .padding(20)
                    .transition(.scale.combined(with: .opacity))
                    .animation(.easeInOut(duration: 0.2), value: t.id)
            }
        }
        .background(WindowTitleSetter(title: viewModel.windowTitle))
    }
    
    private func indicatorColor(_ indicator: VPNViewModel.VPNStatusIndicator) -> Color {
        switch indicator {
        case .connected:
            return .green
        case .inProgress:
            return .yellow
        case .disconnected:
            return .red
        }
    }
    
    private var vpnRow: some View {
        GridRow {
            Text("VPN:")
                .font(.body)
                .gridColumnAlignment(.leading)

            if viewModel.hasProfile, !viewModel.profiles.isEmpty {
                if viewModel.profiles.count <= 1 {
                    Text(viewModel.selectedProfileName.isEmpty ? "—" : viewModel.selectedProfileName)
                        .font(.body)
                        .gridColumnAlignment(.leading)
                } else {
                    let binding = Binding<String>(
                        get: { viewModel.selectedProfileName },
                        set: { viewModel.selectProfileName($0) }
                    )

                    Picker("", selection: binding) {
                        ForEach(viewModel.profiles.map(\.name), id: \.self) { name in
                            Text(name).tag(name)
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                    .disabled(viewModel.statusIndicator != .disconnected ||
                              viewModel.isBusy)
                    .gridColumnAlignment(.leading)
                }
            } else {
                Button("Import...") {
                    isImportingConfig = true
                }
                .disabled(viewModel.isBusy)
                .gridColumnAlignment(.leading)
            }
        }
    }
}

// MARK: - SwiftUI Preview

#Preview("MainView") {
    MainView(viewModel: VPNViewModel(), publicIP: PublicIPViewModel())
}

