/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */
import Darwin

class TestPlugin {
    var name: String
    var version: UInt
    // var statusReports: XPPluginStatusCollator

    init(name: String, version: UInt) {
        self.name = name
        self.version = version
    }
}

@available(macOS 11.0, *)
extension TestPlugin: XProtectPluginProtocol {
    @inline(never)
    func assess() -> XProtectPluginCompletionStatus {
        let testRemediator: some Remediator = TestRemediator {
            File(path: "/tmp/eicar") {
                MinFileSize(68)
                FileYara(XPAPIHelpers.shared.yara.createYaraMatcher(ruleString: """
                    rule EICAR: Example Test {
                        meta:
                            name = "EICAR.A"
                            version = 1337
                            enabled = true
                        strings:
                            $eicar_substring = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
                        condition:
                            $eicar_substring
                    }
                    """))
            }

            File(searchDir: "/tmp", regexp: "[0-9]{5,10}", searchDepth: 1) {
                MinFileSize(24)
            }

            // for targetFilePath in targetFilePaths {
            //     File(path: targetFilePath) {
            //         MinFileSize(constraint: 10)
            //     }
            // }

            // if isRoot() {
            //     File(path: "/tmp/hoge") {
            //         MinFileSize(constraint: 10)
            //     }
            //     File(path: "/tmp/fuga") {
            //         MinFileSize(constraint: 30)
            //     }
            // }
        }
        testRemediator.assess()
        return .success
    }
}

struct TestRemediator {
    // var statusReports: XPPluginAPI.XPPluginStatusCollator
    var remediations: Remediations
    
    @inline(never)
    init(@RemediationArrayBuilder buildRemediations: @escaping () -> [any Remediation]) {
        remediations = Remediations(content: buildRemediations())
    }
}
 
extension TestRemediator : Remediator {
    @inline(never)
    func assess() {
        // For demonstration purposes, we only print the results of the remediations without actually deleting files
        for remediation in remediations.content {
            if let fileRemediation = remediation as? FileRemediation {
                let result = fileRemediation.conditions.allSatisfy {$0._assess(fileRemediation.filepath)}
                if result {
                    print("\(fileRemediation.filepath) Matched")
                }
            }
        }
    }
}

func isRoot() -> Bool {
    return getuid() == 0
}

let targetFilePaths = [
    "/tmp/eicar",
    "/tmp/hoge",
    "/tmp/fuga",
]

@available(macOS 11.0, *)
@inline(never)
func main() {
    let status = TestPlugin(name: "TestPlugin", version: 1).assess()
    print("Exit status: \(status)")
}

if #available(macOS 11.0, *) {
    main()
} else {
    // Fallback on earlier versions
}

