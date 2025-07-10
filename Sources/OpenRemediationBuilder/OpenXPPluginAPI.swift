/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */
import os
import yara

enum XProtectPluginCompletionStatus {
    case success
    case failure
}

protocol XProtectPluginProtocol {
    var name: String { get }
    var version: UInt { get }
    func main(api: XPAPIHelpersProtocol) -> XProtectPluginCompletionStatus
    func assess() -> XProtectPluginCompletionStatus
}

extension XProtectPluginProtocol {
    func main(api: XPAPIHelpersProtocol) -> XProtectPluginCompletionStatus {
        return assess()
    }
}

@available(macOS 11.0, *)
class XProtectPluginAPIPath {
    var logger: XPLogger
    var totalDeletions: UInt = 0
    var totalFailedDeletions: UInt = 0
    init(logger: XPLogger, totalDeletions: UInt, totalFailedDeletions: UInt) {
        self.logger = logger
        self.totalDeletions = totalDeletions
        self.totalFailedDeletions = totalFailedDeletions
    }
}

@available(macOS 11.0, *)
class XPAPIHelpers { // accessor 0x100070950
    /* fields */
    let logger: XPLogger
    var pluginService: Any // __C.XProtectPluginDispatchProtocol
    let codeSignature: Any // XPPluginAPI.XProtectPluginCodeSignatureAPIProtocol
    let file: XProtectPluginAPIPath
    var launchd: Any // XPPluginAPI.XProtectPluginLaunchdAPIProtocol
    var launchServices: Any // XPPluginAPI.XPLaunchServicesProtocol
    var yara: XProtectPluginAPIYaraProtocol
    let process: Any // XPPluginAPI.XProtectPluginProcessAPIProtocol
    var event: Any // XPPluginAPI.XProtectPluginAPIEventsProtocol
    let networkSettings: Any // XPPluginAPI.XProtectPluginAPINetworkSettingsProtocol
    var keychain: Any // XPPluginAPI.XProtectPluginKeychainAPIProtocol
    var plugin: Any // XPPluginAPI.XProtectPluginProtocol ?
    var pipeline: Any // _OBJC_CLASS_$_CPProfile ?
    var connection: Any // XPPluginAPI.VerifiableXPCConnectionProtocol
    var configProfiles: Any // XPPluginAPI.XProtectConfigProfilesAPIProtocol
    var alertGUI: Any // lazy XPPluginAPI.XPAlertGUIProtocol ?
    var memory: Any // XPProcessMemoryAPI
    var behavioralEvents: Any // lazy XPPluginAPI.XPEventDatabaseAPIProtocol ??
    private init() {
        self.logger = XPLogger()
        self.pluginService = 0
        self.codeSignature = 0
        self.file = XProtectPluginAPIPath(logger: XPLogger(), totalDeletions: 0, totalFailedDeletions: 0)
        self.launchd = 0
        self.launchServices = 0
        self.yara = XProtectPluginAPIYara()
        self.process = 0
        self.event = 0
        self.networkSettings = 0
        self.keychain = 0
        self.plugin = 0
        self.pipeline = 0
        self.connection = 0
        self.configProfiles = 0
        self.alertGUI = 0
        self.memory = 0
        self.behavioralEvents = 0
    }

    static let shared = XPAPIHelpers()
}

// XPPluginAPI
protocol XPPluginPathProtocol {
//   /* signature requirements */
//    A: _OBJC_CLASS_$_CPProfile // key_arg: true, extra_arg: false, kind: protocol
    
}

@available(macOS 11.0, *)
class XPLogger {
    var logger: Logger?
}

class YaraMatcher {
    var description: String
    var compiler: UnsafeMutablePointer<_YR_COMPILER>?
    var rules: UnsafeMutablePointer<YR_RULES>?
    let signpost_compile_name: String // _OBJC_CLASS_$_CPProfile
    let callbackV3: (() -> Void)? // _OBJC_CLASS_$_CPProfile _$sAA_SvSgABtXC
    let callbackV4: (() -> Void)? // _OBJC_CLASS_$_CPProfile _$sSvSg_Aa2BtXC
    init(description: String, compiler: UnsafeMutablePointer<_YR_COMPILER>? = nil, rules: UnsafeMutablePointer<YR_RULES>? = nil, signpost_compile_name: String, callbackV3: (() -> Void)?, callbackV4: ( () -> Void)?) {
        self.description = description
        self.compiler = compiler
        self.rules = rules
        self.signpost_compile_name = signpost_compile_name
        self.callbackV3 = callbackV3
        self.callbackV4 = callbackV4
    }
}

protocol XPAPIHelpersProtocol {
    
}

class XProtectPluginAPIYara {
    /* fields */
    var api: XPAPIHelpersProtocol?
}


    
@available(macOS 11.0, *)
class XPPluginPath {
    let logger: XPLogger
    var url: String // _OBJC_CLASS_$_CPProfile
    init(logger: XPLogger, url: String) {
        self.logger = logger
        self.url = url
    }
}

@available(macOS 11.0, *)
extension XPPluginPath: XPPluginPathProtocol {

}

protocol YaraMatcherProtocol {
    func match(path: String) -> Bool
}

extension YaraMatcher:  YaraMatcherProtocol {
    func match(path: String) -> Bool {
        let matchResult = UnsafeMutablePointer<Bool>.allocate(capacity: 1)
        defer { matchResult.deallocate() }
        matchResult.initialize(to: false)
        
        let callback: YR_CALLBACK_FUNC = { (context, message, message_data, user_data) -> Int32 in
            guard let user_data = user_data else { return CALLBACK_ERROR }
            let matchResult = user_data.assumingMemoryBound(to: Bool.self)
            matchResult.pointee = true
            return CALLBACK_ABORT
        }
        if yr_rules_scan_file(rules, path, 0, callback, matchResult, 0) != ERROR_SUCCESS {
            print("YARA scan failed")
            return false
        }
        
        return matchResult.pointee
    }
}

protocol XProtectPluginAPIYaraProtocol {
    func createYaraMatcher(ruleString: String) -> any YaraMatcherProtocol
}

extension XProtectPluginAPIYara : XProtectPluginAPIYaraProtocol {
    func createYaraMatcher(ruleString: String) -> any YaraMatcherProtocol {
        if yr_initialize() != ERROR_SUCCESS {
            print("Failed to initialize YARA")
        }

        var maxStrings: Int32 = 10000
        let configStatus = withUnsafeMutablePointer(to: &maxStrings) { ptr in
            yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, ptr)
        }
        if configStatus != ERROR_SUCCESS {
            print("Failed to set YARA configuration")
        }
        
        var compiler: UnsafeMutablePointer<YR_COMPILER>?
        let compilerStatus = yr_compiler_create(&compiler)
        if compilerStatus != ERROR_SUCCESS {
            print("Failed to create YARA compiler \(compilerStatus)")
        }
        
        var errorMessage = ""
        let errorCallback: YR_COMPILER_CALLBACK_FUNC = { (errorLevel, fileName, lineNumber, ruleName, message, userData) in
            if let userData = userData {
                let errorMessagePtr = userData.assumingMemoryBound(to: String.self)
                if let message = message {
                    let errorString = String(cString: message)
                    errorMessagePtr.pointee = "Error at line \(lineNumber): \(errorString)"
                }
            }
        }
        yr_compiler_set_callback(compiler, errorCallback, &errorMessage)
        
        let addStringStatus = yr_compiler_add_string(compiler, ruleString, nil)
        if addStringStatus != ERROR_SUCCESS {
            print("Failed to add rule \(addStringStatus)")
            if !errorMessage.isEmpty {
                print("Compiler error: \(errorMessage)")
            }
        }
        
        var rules: UnsafeMutablePointer<YR_RULES>?
        if yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS {
            print("Failed to compile rules")
        }
        
        return YaraMatcher(description: "YARA", compiler: compiler, rules: rules, signpost_compile_name: "Yara", callbackV3: nil, callbackV4: nil)
    }
}

enum YaraMetaType {
    case NULL
    case Integer
    case String
    case Boolean
}

@available(macOS 11.0, *)
class YaraMeta {
    let logger: XPLogger
    var identifier: String
    let type:  YaraMetaType
    let intValue: Int // _OBJC_CLASS_$_CPProfile ?
    let stringValue: String?
    let boolValue: Bool?
    init(logger: XPLogger, identifier: String, type: YaraMetaType, intValue: Int, stringValue: String?, boolValue: Bool?) {
        self.logger = logger
        self.identifier = identifier
        self.type = type
        self.intValue = intValue
        self.stringValue = stringValue
        self.boolValue = boolValue
    }
}

@available(macOS 11.0, *)
class YaraRule {
    var identifier: String
    var metadata: [YaraMeta] // Swift.Array -> XPPluginAPI.YaraMeta
    var tags: [String]
    init(identifier: String, metadata: [YaraMeta], tags: [String]) {
        self.identifier = identifier
        self.metadata = metadata
        self.tags = tags
    }
}

protocol YaraRuleProtocol {
    
}

@available(macOS 11.0, *)
extension YaraRule : YaraRuleProtocol {
    
}

class YaraScanResult { // accessor 0x100077ca0
    var matching: [YaraRuleProtocol] = [] // Swift.Array -> XPPluginAPI.YaraRuleProtocol
    var nonMatching: [YaraRuleProtocol] = [] // Swift.Array -> XPPluginAPI.YaraRuleProtocol
}
