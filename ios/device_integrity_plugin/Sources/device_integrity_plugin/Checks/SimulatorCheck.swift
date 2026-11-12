import Foundation

/// Detects whether the app is running in an iOS Simulator.
///
/// Uses compile-time and runtime indicators. Reported separately
/// from jailbreak — a simulator is not a compromised device.
class SimulatorCheck: IntegrityCheck {

    func execute() -> [Finding] {
        var indicators: [String] = []

        // Compile-time check: TARGET_OS_SIMULATOR is set at build time
        #if targetEnvironment(simulator)
        indicators.append("target_environment_simulator")
        #endif

        // Runtime checks
        let model = ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"]
        if model != nil {
            indicators.append("simulator_device_name_env")
        }

        let simulatorRuntime = ProcessInfo.processInfo.environment["SIMULATOR_RUNTIME_VERSION"]
        if simulatorRuntime != nil {
            indicators.append("simulator_runtime_version_env")
        }

        // Check hardware model string
        var systemInfo = utsname()
        uname(&systemInfo)
        let machine = withUnsafePointer(to: &systemInfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(cString: $0)
            }
        }
        // Simulators report architecture like "x86_64" or "arm64" without
        // device-specific model numbers
        if machine.contains("x86_64") || machine.contains("i386") {
            indicators.append("x86_architecture:\(machine)")
        }

        if !indicators.isEmpty {
            return [.detected(
                "emulator_simulator",
                "simulator_indicators",
                indicators.joined(separator: ", ")
            )]
        }
        return [.notDetected("emulator_simulator", "no_simulator_indicators")]
    }
}
