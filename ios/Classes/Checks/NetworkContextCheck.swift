import Foundation

/// Reports network context: proxy configuration and VPN status.
///
/// These are separate signals that never influence the jailbreak verdict.
/// A proxy or VPN alone is not evidence of compromise.
class NetworkContextCheckiOS: IntegrityCheck {

    func execute() -> [Finding] {
        var findings: [Finding] = []

        // ── Proxy configuration ─────────────────────────────────────────
        findings.append(checkProxy())

        // ── VPN status ──────────────────────────────────────────────────
        findings.append(checkVpn())

        return findings
    }

    private func checkProxy() -> Finding {
        // Check system proxy settings via CFNetwork
        guard let proxySettings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return .notDetected("proxy_configured", "no_proxy_settings")
        }

        let httpProxy = proxySettings[kCFNetworkProxiesHTTPProxy as String] as? String
        let httpsProxy = proxySettings[kCFNetworkProxiesHTTPSProxy as String] as? String
        let httpEnabled = proxySettings[kCFNetworkProxiesHTTPEnable as String] as? Int
        let httpsEnabled = proxySettings["HTTPSEnable"] as? Int

        var details: [String] = []
        if let proxy = httpProxy, httpEnabled == 1 {
            details.append("http:\(proxy)")
        }
        if let proxy = httpsProxy, httpsEnabled == 1 {
            details.append("https:\(proxy)")
        }

        if !details.isEmpty {
            return .detected(
                "proxy_configured",
                "proxy_configured",
                details.joined(separator: ", ")
            )
        }
        return .notDetected("proxy_configured", "no_proxy")
    }

    private func checkVpn() -> Finding {
        // Check network interfaces for VPN-related types
        // (utun, ipsec, ppp are common VPN interface prefixes)
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return .error("vpn_active", "getifaddrs_failed")
        }
        defer { freeifaddrs(ifaddr) }

        let vpnPrefixes = ["utun", "ipsec", "ppp", "tap", "tun"]
        var vpnInterfaces: [String] = []

        var ptr = firstAddr
        while true {
            let name = String(cString: ptr.pointee.ifa_name)
            for prefix in vpnPrefixes {
                if name.hasPrefix(prefix) {
                    if !vpnInterfaces.contains(name) {
                        vpnInterfaces.append(name)
                    }
                }
            }
            guard let next = ptr.pointee.ifa_next else { break }
            ptr = next
        }

        if !vpnInterfaces.isEmpty {
            return .detected(
                "vpn_active",
                "vpn_interface_active",
                vpnInterfaces.joined(separator: ", ")
            )
        }
        return .notDetected("vpn_active", "no_vpn_interface")
    }
}
