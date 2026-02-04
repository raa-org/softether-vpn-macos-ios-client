//
//  AppInfo.swift
//  SimpleTunnel

import Foundation

enum AppInfo {

    static var hostVersionText: String {
        let bundle = Bundle.main
        let version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "–"
        let build   = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "–"
        return "App \(version) (\(build))"
    }

    static var extensionVersionText: String {
        guard let extBundle = systemExtensionBundle else {
            return "Extension –"
        }

        let version = extBundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "–"
        let build   = extBundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "–"
        return "Extension \(version) (\(build))"
    }

    // MARK: - Private

    private static var systemExtensionBundle: Bundle? {
        let baseURL = Bundle.main.bundleURL
            .appendingPathComponent("Contents")
            .appendingPathComponent("Library")
            .appendingPathComponent("SystemExtensions")

        let specific = baseURL.appendingPathComponent(VPNConfiguration.systemExtensionBundleIDWithSuffix)
        if let bundle = Bundle(url: specific) {
            return bundle
        }

        return nil
    }
}

