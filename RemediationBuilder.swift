import Foundation

// MARK: - Protocols

protocol Condition {
    associatedtype Subject
}

protocol Constraint {
    associatedtype Constraint
}

protocol ServiceCondition: Constraint {
    associatedtype A: Condition & ServiceConditionConvertible where A.Subject == XProtectLaunchdDaemonAgentProtocol
}

protocol ProcessCondition: Constraint {
    associatedtype A: Condition & ProcessConditionConvertible where A.Subject == XPProcessProtocol
}

protocol FileCondition: Constraint {
    associatedtype A: Condition & FileConditionConvertible where A.Subject == XPPluginPathProtocol
}

protocol SafariAppExtensionCondition: Constraint {
    associatedtype A: Condition & SafariAppExtensionConditionConvertible where A.Subject == XPRegisteredPlugin
}

protocol Remediation {
    associatedtype A: RemediationConvertible
}

protocol OnMatchable {
    associatedtype Subject
}

protocol RemediationConvertible {}

protocol ServiceConditionConvertible {}
protocol ProcessConditionConvertible {}
protocol FileConditionConvertible {}
protocol SafariAppExtensionConditionConvertible {}

protocol Remediator {}

// MARK: - Value Enum

enum Value: Equatable {
    case pattern(String)
    case string(String)
    case bool(Bool)
    case int(Int)
    case patternGroup([String])
    case stringGroup([String])
    case intGroup([Int])
    case stringPrefix(String)
    case stringSuffix(String)
    case stringContains(String)
    case wildcard
}

// MARK: - Service Conditions

struct AnyServiceCondition: ServiceCondition, ServiceConditionConvertible, Condition {
    var constraint: Any
    let _assess: (XProtectLaunchdDaemonAgentProtocol) -> Bool
    typealias A = AnyServiceCondition
}

struct ArgumentCount: ServiceCondition, ServiceConditionConvertible, Condition {
    var constraint: Int
    typealias A = ArgumentCount
}

struct Arguments: ServiceCondition, ServiceConditionConvertible, Condition {
    var constraint: [Int: Value]
    typealias A = Arguments
}

struct KeyValue: ServiceCondition, ServiceConditionConvertible, Condition {
    var constraint: [String: Value]
    typealias A = KeyValue
}

struct ExecutableYara: ServiceCondition, ServiceConditionConvertible, Condition {
    var constraint: YaraMatcherProtocol
    typealias A = ExecutableYara
}

struct ExecutablePath: ServiceCondition, ServiceConditionConvertible, Condition {
    var constraint: Value
    typealias A = ExecutablePath
}

struct ExecutableIsUntrusted: ServiceCondition, ServiceConditionConvertible, Condition {
    var constraint: Bool
    let logger: XPLogger
    typealias A = ExecutableIsUntrusted
}

struct ExecutableRevoked: ServiceCondition, ServiceConditionConvertible, Condition {
    var constraint: Bool
    let logger: XPLogger
    typealias A = ExecutableRevoked
}

// MARK: - Process Conditions

struct AnyProcessCondition: ProcessCondition, ProcessConditionConvertible, Condition {
    var constraint: Any
    let _assess: (XPProcessProtocol) -> Bool
    typealias A = AnyProcessCondition
}

struct ProcessName: ProcessCondition, ProcessConditionConvertible, Condition {
    var constraint: Value
    typealias A = ProcessName
}

struct ProcessCDHash: ProcessCondition, ProcessConditionConvertible, Condition {
    var constraint: String
    typealias A = ProcessCDHash
}

struct ProcessIsNotarised: ProcessCondition, ProcessConditionConvertible, Condition {
    var constraint: Bool
    typealias A = ProcessIsNotarised
}

struct ProcessIsAppleSigned: ProcessCondition, ProcessConditionConvertible, Condition {
    var constraint: Bool
    typealias A = ProcessIsAppleSigned
}

struct ProcessMainExecutable: ProcessCondition, ProcessConditionConvertible, Condition {
    var constraint: [AnyFileCondition]
    typealias A = ProcessMainExecutable
}

struct ProcessHasBackingFile: ProcessCondition, ProcessConditionConvertible, Condition {
    var constraint: Bool
    typealias A = ProcessHasBackingFile
}

struct HasLoadedLibrary: ProcessCondition, ProcessConditionConvertible, Condition {
    var constraint: Value
    typealias A = HasLoadedLibrary
}

// MARK: - File Conditions

struct AnyFileCondition: FileCondition, FileConditionConvertible, Condition {
    var constraint: Any
    let _assess: (XPPluginPathProtocol) -> Bool
    typealias A = AnyFileCondition
}

struct FileYara: FileCondition, FileConditionConvertible, Condition {
    var constraint: YaraMatcherProtocol
    typealias A = FileYara
}

struct FilePath: FileCondition, FileConditionConvertible, Condition {
    var constraint: Value
    typealias A = FilePath
}

struct FileMime: FileCondition, FileConditionConvertible, Condition {
    var constraint: Value
    typealias A = FileMime
}

struct FileMagic: FileCondition, FileConditionConvertible, Condition {
    var constraint: Value
    typealias A = FileMagic
}

struct FileMacho: FileCondition, FileConditionConvertible, Condition {
    var constraint: Bool
    let logger: XPLogger
    typealias A = FileMacho
}

struct FileNotarised: FileCondition, FileConditionConvertible, Condition {
    var constraint: Bool
    let logger: XPLogger
    typealias A = FileNotarised
}

struct FileSingleByteXor: FileCondition, FileConditionConvertible, Condition {
    var constraint: [AnyFileCondition]
    private var xor_key: UInt8?
    let logger: XPLogger
    typealias A = FileSingleByteXor
}

struct MaxFileSize: FileCondition, FileConditionConvertible, Condition {
    var constraint: Int
    typealias A = MaxFileSize
}

struct MinFileSize: FileCondition, FileConditionConvertible, Condition {
    var constraint: Int
    typealias A = MinFileSize
}

struct FileSHA256: FileCondition, FileConditionConvertible, Condition {
    var constraint: String
    typealias A = FileSHA256
}

struct FileCDHash: FileCondition, FileConditionConvertible, Condition {
    var constraint: String
    let logger: XPLogger
    typealias A = FileCDHash
}

// MARK: - Safari App Extension Conditions

struct AnySafariAppExtensionCondition: SafariAppExtensionCondition, SafariAppExtensionConditionConvertible, Condition {
    var constraint: Any
    let _assess: (XPRegisteredPlugin) -> Bool
    typealias A = AnySafariAppExtensionCondition
}

struct ExtensionBinaryYara: SafariAppExtensionCondition, SafariAppExtensionConditionConvertible, Condition {
    var constraint: YaraMatcherProtocol
    typealias A = ExtensionBinaryYara
}

struct JavaScriptYara: SafariAppExtensionCondition, SafariAppExtensionConditionConvertible, Condition {
    var constraint: YaraMatcherProtocol
    typealias A = JavaScriptYara
}

// MARK: - Remediations

struct ProxyRemediation: Remediation, RemediationConvertible {
    var tag: String?
    var reportOnly: Bool
    var followUpRemediations: [Remediation]
    let hosts: [String]
    let ports: [Int]
    typealias A = ProxyRemediation
}

struct ServiceRemediation: Remediation, OnMatchable, RemediationConvertible {
    var tag: String?
    var reportOnly: Bool
    var unloadOnly: Bool
    var deleteBundleToo: Bool
    var conditions: [AnyServiceCondition]
    var followUpRemediations: [Remediation]
    var onMatchCallbacks: [([RemediationConvertible]) -> (XProtectLaunchdDaemonAgentProtocol) -> Void]
    typealias A = ServiceRemediation
}

struct FileRemediation: Remediation, RemediationConvertible {
    var tag: String?
    var reportOnly: Bool
    var followUpRemediations: [Remediation]
    var conditions: [AnyFileCondition]
    var filepath: XPPluginPathProtocol
    typealias A = FileRemediation
}

struct SafariAppExtensionRemediation: Remediation, RemediationConvertible {
    var tag: String?
    var reportOnly: Bool
    var followUpRemediations: [Remediation]
    var conditions: [AnySafariAppExtensionCondition]
    typealias A = SafariAppExtensionRemediation
}

struct ProcessRemediation: Remediation, RemediationConvertible {
    var tag: String?
    var reportOnly: Bool
    var deleteExecutable: Bool
    var includePlatform: Bool
    var followUpRemediations: [Remediation]
    var conditions: [AnyProcessCondition]
    typealias A = ProcessRemediation
}

// MARK: - Builders

enum RemediationArrayBuilder {}

struct Remediations {
    var content: [Remediation]
}

enum ServiceRemediationBuilder {}

struct Service {
    var content: ServiceRemediation
    var unloadOnlyBool: Bool
}

struct Proxy {
    var hosts: [String]
    var ports: [Int]
}

enum FileRemediationBuilder {}

struct File {
    var paths: [XPPluginPathProtocol]
    var predicate: NSPredicate?
    var searchDir: String?
    var searchDepth: Int?
    var regexpArray: [String]
    var isFileSearchRemediation: Bool
    var isPredicateSearchRemediation: Bool
    var reportOnlyBool: Bool
    var conditions: [AnyFileCondition]
}

enum SafariAppExtensionRemediationBuilder {}

struct SafariAppExtension {
    var conditions: [AnySafariAppExtensionCondition]
    var reportOnlyBool: Bool
}

struct Process {
    var processConditions: [AnyProcessCondition]
    var reportOnlyBool: Bool
    var deleteExecutableBool: Bool
    var includePlatformBool: Bool
}

enum ProcessRemediationBuilder {}

// MARK: - Extensions

extension Array: RemediationConvertible where Element: Remediation {}
extension Array: ServiceConditionConvertible where Element: ServiceCondition & ServiceConditionConvertible {}
extension Array: FileConditionConvertible where Element: FileCondition & FileConditionConvertible {}

extension Service: RemediationConvertible {}
extension Proxy: RemediationConvertible {}
extension File: RemediationConvertible {}
extension SafariAppExtension: RemediationConvertible {}
extension Process: RemediationConvertible {}

// MARK: - Protocol Conformance Extensions

extension AnyServiceCondition {
    typealias Constraint = Any
    typealias Subject = XProtectLaunchdDaemonAgentProtocol
}

extension AnyProcessCondition {
    typealias Constraint = Any
    typealias Subject = XPProcessProtocol
}

extension ArgumentCount {
    typealias Constraint = Int
    typealias Subject = XProtectLaunchdDaemonAgentProtocol
}

extension Arguments {
    typealias Constraint = [Int: Value]
    typealias Subject = XProtectLaunchdDaemonAgentProtocol
}

extension KeyValue {
    typealias Constraint = [String: Value]
    typealias Subject = XProtectLaunchdDaemonAgentProtocol
}

extension ExecutableYara {
    typealias Constraint = YaraMatcherProtocol
    typealias Subject = XProtectLaunchdDaemonAgentProtocol
}

extension ExecutablePath {
    typealias Constraint = Value
    typealias Subject = XProtectLaunchdDaemonAgentProtocol
}

extension ExecutableIsUntrusted {
    typealias Constraint = Bool
    typealias Subject = XProtectLaunchdDaemonAgentProtocol
}

extension ExecutableRevoked {
    typealias Constraint = Bool
    typealias Subject = XProtectLaunchdDaemonAgentProtocol
}

extension AnyFileCondition {
    typealias Constraint = Any
    typealias Subject = XPPluginPathProtocol
}

extension FileYara {
    typealias Constraint = YaraMatcherProtocol
    typealias Subject = XPPluginPathProtocol
}

extension FilePath {
    typealias Constraint = Value
    typealias Subject = XPPluginPathProtocol
}

extension FileMime {
    typealias Constraint = Value
    typealias Subject = XPPluginPathProtocol
}

extension FileMagic {
    typealias Constraint = Value
    typealias Subject = XPPluginPathProtocol
}

extension FileMacho {
    typealias Constraint = Bool
    typealias Subject = XPPluginPathProtocol
}

extension FileNotarised {
    typealias Constraint = Bool
    typealias Subject = XPPluginPathProtocol
}

extension FileSingleByteXor {
    typealias Constraint = [AnyFileCondition]
    typealias Subject = XPPluginPathProtocol
}

extension MaxFileSize {
    typealias Constraint = Int
    typealias Subject = XPPluginPathProtocol
}

extension MinFileSize {
    typealias Constraint = Int
    typealias Subject = XPPluginPathProtocol
}

extension FileSHA256 {
    typealias Constraint = String
    typealias Subject = XPPluginPathProtocol
}

extension FileCDHash {
    typealias Constraint = String
    typealias Subject = XPPluginPathProtocol
}

extension AnySafariAppExtensionCondition {
    typealias Constraint = Any
    typealias Subject = XPRegisteredPlugin
}

extension ExtensionBinaryYara {
    typealias Constraint = YaraMatcherProtocol
    typealias Subject = XPRegisteredPlugin
}

extension JavaScriptYara {
    typealias Constraint = YaraMatcherProtocol
    typealias Subject = XPRegisteredPlugin
}

extension ProcessName {
    typealias Constraint = Value
    typealias Subject = XPProcessProtocol
}

extension ProcessCDHash {
    typealias Constraint = String
    typealias Subject = XPProcessProtocol
}

extension ProcessIsNotarised {
    typealias Constraint = Bool
    typealias Subject = XPProcessProtocol
}

extension ProcessIsAppleSigned {
    typealias Constraint = Bool
    typealias Subject = XPProcessProtocol
}

extension ProcessMainExecutable {
    typealias Constraint = [AnyFileCondition]
    typealias Subject = XPProcessProtocol
}

extension ServiceExecutable {
    typealias Constraint = [AnyFileCondition]
    typealias Subject = XProtectLaunchdDaemonAgentProtocol
}

extension ProcessHasBackingFile {
    typealias Constraint = Bool
    typealias Subject = XPProcessProtocol
}

extension HasLoadedLibrary {
    typealias Constraint = Value
    typealias Subject = XPProcessProtocol
}

extension ServiceRemediation {
    typealias Subject = XProtectLaunchdDaemonAgentProtocol
}

struct ServiceExecutable: ServiceCondition, ServiceConditionConvertible, Condition {
    var constraint: [AnyFileCondition]
    typealias A = ServiceExecutable
}

@main
struct RemediationBuilder {
    static func main() {
        print("Hello, world!")
    }
}
