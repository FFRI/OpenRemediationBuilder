/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */
import Foundation

struct File {
    var paths: [String] = [] // NOTE: For simplicity, we use [String] instead of [XPPluginPathProtocol]
    var predicate: NSPredicate? = nil
    var searchDir: String? = nil
    var searchDepth: Int? = nil
    var regexpArray: [String] = []
    var isFileSearchRemediation: Bool = false
    var isPredicateSearchRemediation: Bool = false
    var reportOnlyBool: Bool = false
    var conditions: [AnyFileCondition] = []
    
    // For remediating a single file
    @inline(never)
    init(path: String, @FileRemediationBuilder fileRemediationBuilder: @escaping () -> [AnyFileCondition]) {
        self.paths = [path]
        self.conditions = fileRemediationBuilder()
    }

    // For remediating files in a specified directory with a specified depth (not implemented)
    @inline(never)
    init(searchDir: String, regexp: String, searchDepth: Int?, @FileRemediationBuilder fileRemediationBuilder: @escaping () -> [AnyFileCondition]) {
        self.searchDir = searchDir
        self.searchDepth = searchDepth
        self.isFileSearchRemediation = true;
        self.regexpArray.append(regexp)
        self.conditions = fileRemediationBuilder()
    }

    // For remediating files that match a specified predicate (not implemented)
    @inline(never)
    init(predicate: NSPredicate, @FileRemediationBuilder fileRemediationBuilder: @escaping () -> [AnyFileCondition]) {
        self.predicate = predicate
        self.isPredicateSearchRemediation = true
        self.conditions = fileRemediationBuilder()
    }

    func reportOnly() -> Self {
        var copy = self
        copy.reportOnlyBool = true
        return copy
    }
}

extension File: RemediationConvertible {
    @inline(never)
    func asRemediation() -> [any Remediation] {
        if self.isFileSearchRemediation {
            return self.fileSearchRemediations()
        } else if self.isPredicateSearchRemediation {
            return self.predicateSearchRemediations()
        } else {
            return [
                FileRemediation(reportOnly: self.reportOnlyBool, followUpRemediations: [], conditions: self.conditions, filepath: paths[0])
            ]
        }
    }
    
    private func fileSearchRemediations() -> [any Remediation] {
        guard let searchDir = self.searchDir else {
            print("Error: searchDir is nil for file search remediation")
            return []
        }
        
        var remediations: [any Remediation] = []
        let maxDepth = self.searchDepth ?? 1
        let enumerator = FileManager.default.enumerator(atPath: searchDir)
        
        while let relativePath = enumerator?.nextObject() as? String {
            let fullPath = (searchDir as NSString).appendingPathComponent(relativePath)
            
            let pathComponents = relativePath.components(separatedBy: "/")
            if pathComponents.count > maxDepth {
                continue
            }
            
            for pattern in self.regexpArray {
                do {
                    let regex = try NSRegularExpression(pattern: pattern, options: [])
                    let range = NSRange(location: 0, length: fullPath.count)
                    if regex.firstMatch(in: fullPath, options: [], range: range) != nil {
                        remediations.append(
                            FileRemediation(
                                reportOnly: self.reportOnlyBool,
                                followUpRemediations: [],
                                conditions: self.conditions,
                                filepath: fullPath
                            )
                        )
                        break
                    }
                } catch {
                    print("Error creating regex for pattern '\(pattern)': \(error)")
                    continue
                }
            }
        }
        
        return remediations
    }
    
    private func predicateSearchRemediations() -> [any Remediation] {
        print("Error: predicateSearchRemediations is not implemented")
        return []
    }
}

protocol Condition {
    associatedtype Subject
}

/* signature requirements */
//  A: RemediationBuilder.Condition // key_arg: true, extra_arg: false, kind: protocol
//  A: RemediationBuilder.FileConditionConvertible // key_arg: true, extra_arg: false, kind: protocol
//  RemediationBuilder.Condition.Subject ==: XPPluginAPI.XPPluginPathProtocol // key_arg: false, extra_arg: false, kind: same-type
protocol FileCondition: FileConditionConvertible, Condition where Subject == String {
    associatedtype Constraint
    var constraint: Constraint { get set }
}

protocol FileConditionConvertible {
    func asAnyFileCondition() -> [AnyFileCondition]
}

// protocol conformance nominal type descriptor for Swift.Array : RemediationBuilder.FileConditionConvertible {
//   /* conditional requirements */
//    < where A: RemediationBuilder.AnyFileCondition >
// }
extension Array<AnyFileCondition>: FileConditionConvertible {
    @inline(never)
    func asAnyFileCondition() -> [AnyFileCondition] {
        self
    }
}

struct AnyFileCondition : FileCondition {
    typealias Constraint = Any
    typealias Subject = String

    var constraint: Constraint
    let _assess: (String) -> Bool // NOTE: For simplicity, we use (String) -> Bool instead of XPPluginPathProtocol -> Bool

    func asAnyFileCondition() -> [AnyFileCondition] {
        return [
            self
        ]
    }
}

@inline(never)
func getFileSize(atPath path: String) -> Int64? {
    let fileManager = FileManager.default
    do {
        let attributes = try fileManager.attributesOfItem(atPath: path)
        if let fileSize = attributes[.size] as? Int64 {
            return fileSize
        }
    } catch {
        print("Error: \(error.localizedDescription)")
    }
    return nil
}

struct MinFileSize : FileCondition {
    typealias Constraint = Int

    var constraint: Constraint
    init(_ constraint: Constraint) {
        self.constraint = constraint
    }

    @inline(never)
    func asAnyFileCondition() -> [AnyFileCondition] {
        return [
            AnyFileCondition(constraint: constraint, _assess: { (path: Subject) -> Bool in
                if let fileSize = getFileSize(atPath: path) {
                    return constraint < fileSize
                } else {
                    return false
                }
            })
        ]
    }
}

struct FileYara : FileCondition {
    typealias Constraint = YaraMatcherProtocol
    typealias Subject = String

    var constraint: Constraint
    init(_ constraint: Constraint) {
        self.constraint = constraint
    }

    func match(path: Subject) -> Bool {
        constraint.match(path: path)
    }

    @inline(never)
    func asAnyFileCondition() -> [AnyFileCondition] {
        return [
            AnyFileCondition(constraint: self.constraint, _assess: self.match)
        ]
    }
}

protocol Remediation {
    //
    // A: RemediationBuilder.RemediationConvertible // key_arg: true, extra_arg: false, kind: protocol
}

protocol RemediationConvertible {
    func asRemediation() -> [any Remediation]
}

// protocol conformance nominal type descriptor for Swift.Array : RemediationBuilder.RemediationConvertible {
//   /* conditional requirements */
//    < where A: RemediationBuilder.Remediation >
// }
extension Array<Remediation>: RemediationConvertible {
    @inline(never)
    func asRemediation() -> [any Remediation] {
        self
    }
}

struct FileRemediation {
    var tag: String?
    var reportOnly: Bool
    var followUpRemediations: [any Remediation]
    var conditions: [AnyFileCondition]
    var filepath: String // XPPluginAPI.XPPluginPathProtocol
}

extension FileRemediation : Remediation {

}

extension FileRemediation : RemediationConvertible {
    @inline(never)
    func asRemediation() -> [any Remediation] {
        return [
            self
        ]
    }
}

struct Remediations {
    var content: [any Remediation]
}

protocol Remediator {
    func assess()
}

@resultBuilder enum FileRemediationBuilder {
    @inline(never)
    static func buildBlock(_ components: FileConditionConvertible...) -> [AnyFileCondition] {
        components.map {$0.asAnyFileCondition()}.flatMap {$0.map {$0}}
    }

    @inline(never)
    static func buildOptional(_ component: FileConditionConvertible?) -> [AnyFileCondition] {
        component?.asAnyFileCondition() ?? []
    }

    @inline(never)
    static func buildArray(_ components: [FileConditionConvertible]) -> [AnyFileCondition] {
        components.map {$0.asAnyFileCondition()}.flatMap {$0.map {$0}}
    }
}

@resultBuilder enum RemediationArrayBuilder {
    @inline(never)
    static func buildBlock(_ components: RemediationConvertible...) -> [any Remediation] {
        components.map {$0.asRemediation()}.flatMap {$0.map {$0}}
    }

    @inline(never)
    static func buildOptional(_ component: RemediationConvertible?) -> [any Remediation] {
        component?.asRemediation() ?? []
    }

    @inline(never)
    static func buildArray(_ components: [RemediationConvertible]) -> [any Remediation] {
        components.map {$0.asRemediation()}.flatMap {$0.map {$0}}
    }
}
