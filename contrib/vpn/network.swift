import Foundation
import SystemConfiguration

// One request on stdin. Credentials never enter argv or diagnostic output.
struct Request: Decodable {
    let action: String
    let service_id: String
    let username: String?
    let password: String?
    let timeout_seconds: Int?
}

func reply(_ value: [String: Any]) {
    if let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([10]))
    }
}

do {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard data.count <= 8192 else { throw NSError(domain: "request_size", code: 1) }
    let request = try JSONDecoder().decode(Request.self, from: data)
    guard let connection = SCNetworkConnectionCreateWithServiceID(nil, request.service_id as CFString, nil, nil) else {
        throw NSError(domain: "service_unavailable", code: 1)
    }
    func status() -> String {
        guard let probe = SCNetworkConnectionCreateWithServiceID(nil, request.service_id as CFString, nil, nil) else { return "unavailable" }
        switch SCNetworkConnectionGetStatus(probe) {
        case .connected: return "connected"
        case .connecting: return "connecting"
        case .disconnecting: return "disconnecting"
        case .disconnected: return "disconnected"
        default: return "unavailable"
        }
    }
    if request.action == "status" {
        reply(["ok": true, "state": status()])
    } else if request.action == "disconnect" {
        let changed = status() != "disconnected"
        if changed {
            guard SCNetworkConnectionStop(connection, true) else {
                throw NSError(domain: "stop_rejected", code: Int(SCError()))
            }
            let end = Date().addingTimeInterval(20)
            while status() != "disconnected" && Date() < end { Thread.sleep(forTimeInterval: 0.2) }
        }
        guard status() == "disconnected" else { throw NSError(domain: "stop_timeout", code: 1) }
        reply(["ok": true, "state": "disconnected", "changed": changed])
    } else if ["connect", "reconnect"].contains(request.action) {
        if request.action == "connect" && status() == "connected" {
            reply(["ok": true, "state": "connected", "changed": false])
        } else {
            if status() != "disconnected" {
                guard SCNetworkConnectionStop(connection, true) else {
                    throw NSError(domain: "stop_rejected", code: Int(SCError()))
                }
                let end = Date().addingTimeInterval(20)
                while status() != "disconnected" && Date() < end { Thread.sleep(forTimeInterval: 0.2) }
                guard status() == "disconnected" else { throw NSError(domain: "stop_timeout", code: 1) }
            }
            var options: [String: Any] = [:]
            if let username = request.username, let password = request.password {
                options["VPN"] = ["AuthName": username, "AuthPassword": password]
            }
            guard SCNetworkConnectionStart(connection, options.isEmpty ? nil : options as CFDictionary, true) else {
                throw NSError(domain: "start_rejected", code: Int(SCError()))
            }
            let end = Date().addingTimeInterval(Double(min(600, max(30, request.timeout_seconds ?? 360))))
            var connected = false
            while Date() < end {
                Thread.sleep(forTimeInterval: 0.5)
                if status() == "connected" { connected = true; break }
            }
            reply(["ok": connected, "state": status(), "changed": true,
                   "code": connected ? "connected" : "authentication_or_network_timeout"])
        }
    } else {
        throw NSError(domain: "unknown_action", code: 1)
    }
} catch let error as NSError {
    // Never print a decoded request, system dictionaries, or credential material.
    let known = ["request_size", "service_unavailable", "stop_rejected", "stop_timeout", "start_rejected", "unknown_action"]
    reply(["ok": false, "code": known.contains(error.domain) ? error.domain : "invalid_request", "state": "unknown"])
    exit(1)
}
