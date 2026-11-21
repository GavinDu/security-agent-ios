import Foundation

/// Syntax-only preflight for *flat*, public-data JSON objects. Reject duplicate
/// root member names even when their JSON spellings differ via Unicode escapes.
/// The caller MUST impose a byte bound first and still validate the schema.
enum UniqueFlatJSONObjectPolicy {
    static func hasUniqueStringKeys(_ data: Data) -> Bool {
        let bytes = [UInt8](data)
        var cursor = 0
        let count = bytes.count

        func skipWhitespace() {
            while cursor < count && (bytes[cursor] == 0x20 ||
                    bytes[cursor] == 0x09 || bytes[cursor] == 0x0A ||
                    bytes[cursor] == 0x0D) {
                cursor += 1
            }
        }

        func stringToken() -> String? {
            guard cursor < count, bytes[cursor] == 0x22 else { return nil }
            let start = cursor
            cursor += 1
            while cursor < count {
                let byte = bytes[cursor]
                cursor += 1
                if byte == 0x5C { // JSON escape: skip next byte, including quotes
                    guard cursor < count else { return nil }
                    cursor += 1
                    continue
                }
                if byte == 0x22 {
                    // Decode *each key token* so "endp\u006fint" and "endpoint"
                    // compare equal, not merely their original byte spelling.
                    return try? JSONDecoder().decode(
                        String.self, from: Data(bytes[start..<cursor])
                    )
                }
                if byte < 0x20 { return nil }
            }
            return nil
        }

        func scalarValue() -> Bool {
            skipWhitespace()
            guard cursor < count else { return false }
            if bytes[cursor] == 0x22 {
                return stringToken() != nil
            }
            // The QR schema has one positive integer version and strings for
            // all remaining fields. Nested objects, arrays and bools fail.
            let start = cursor
            while cursor < count && bytes[cursor] >= 0x30 &&
                    bytes[cursor] <= 0x39 {
                cursor += 1
            }
            return cursor > start
        }

        skipWhitespace()
        guard cursor < count, bytes[cursor] == 0x7B else { return false }
        cursor += 1
        skipWhitespace()
        var seen = Set<String>()
        // The actual schema requires four public fields; reject empty objects.
        guard cursor < count, bytes[cursor] != 0x7D else { return false }

        while cursor < count {
            skipWhitespace()
            guard let key = stringToken(), !seen.contains(key) else {
                return false
            }
            seen.insert(key)
            skipWhitespace()
            guard cursor < count, bytes[cursor] == 0x3A else { return false }
            cursor += 1
            guard scalarValue() else { return false }
            skipWhitespace()
            guard cursor < count else { return false }
            if bytes[cursor] == 0x7D {
                cursor += 1
                skipWhitespace()
                return cursor == count
            }
            guard bytes[cursor] == 0x2C else { return false }
            cursor += 1
        }
        return false
    }
}
