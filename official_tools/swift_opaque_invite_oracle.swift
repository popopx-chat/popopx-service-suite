// Copyright (c) 2026 POPOPX (popopx.chat)
// SPDX-License-Identifier: AGPL-3.0-only
//
// Independent CryptoKit check of `gateway/app/opaque_invite_codec.py`.
//
// The Python suite proves that the encoder and decoder agree with each other.
// This oracle proves they agree with a second implementation, on the same fixed
// bytes: Apple's HKDF<SHA256> and ChaChaPoly, not the `cryptography` wheel.
//
// Build and run from the repository root:
//
//     swiftc -O -o /tmp/opaque_invite_oracle official_tools/swift_opaque_invite_oracle.swift
//     /tmp/opaque_invite_oracle gateway/app/opaque_invite_vectors.json
//
// Exit status 0 means every published vector sealed, opened, linked and
// tamper-rejected identically. Any mismatch prints the vector name and exits 1.

import CryptoKit
import Foundation

enum OracleError: Error, CustomStringConvertible {
    case message(String)

    var description: String {
        switch self {
        case .message(let text): return text
        }
    }
}

func fail(_ text: String) -> OracleError { .message(text) }

func data(hex: String) throws -> Data {
    let clean = hex.trimmingCharacters(in: .whitespacesAndNewlines)
    guard clean.count % 2 == 0 else { throw fail("odd-length hex: \(clean)") }
    var out = Data(capacity: clean.count / 2)
    var index = clean.startIndex
    while index < clean.endIndex {
        let next = clean.index(index, offsetBy: 2)
        guard let byte = UInt8(clean[index..<next], radix: 16) else {
            throw fail("not hex: \(clean[index..<next])")
        }
        out.append(byte)
        index = next
    }
    return out
}

func hex(_ bytes: Data) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

func b64urlEncode(_ bytes: Data) -> String {
    bytes.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func b64urlDecode(_ text: String) throws -> Data {
    var padded = text
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    let remainder = padded.count % 4
    if remainder != 0 {
        padded += String(repeating: "=", count: 4 - remainder)
    }
    guard let decoded = Data(base64Encoded: padded) else {
        throw fail("not base64url: \(text.prefix(24))…")
    }
    return decoded
}

func string(_ value: Any?, _ name: String) throws -> String {
    guard let text = value as? String else { throw fail("missing string \(name)") }
    return text
}

func run(path: String) throws -> Int {
    let url = URL(fileURLWithPath: path)
    let raw = try Data(contentsOf: url)
    guard let root = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
        throw fail("vectors root is not an object")
    }
    guard try string(root["format"], "format") == "opaque-invite-v1" else {
        throw fail("unexpected format")
    }
    let prefix = try string(root["link_prefix"], "link_prefix")
    guard prefix == "https://popopx.chat/i/v1/" else { throw fail("unexpected link prefix: \(prefix)") }

    let ikm = try data(hex: string(root["ikm_hex"], "ikm_hex"))
    let salt = Data(try string(root["salt_utf8"], "salt_utf8").utf8)
    let info = Data(try string(root["info_utf8"], "info_utf8").utf8)
    let aad = Data(try string(root["aad_utf8"], "aad_utf8").utf8)
    let expectedKey = try data(hex: string(root["key_hex"], "key_hex"))

    let key = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: ikm),
        salt: salt,
        info: info,
        outputByteCount: 32
    )
    let keyBytes = key.withUnsafeBytes { Data($0) }
    guard keyBytes == expectedKey else {
        throw fail("HKDF key mismatch: CryptoKit \(hex(keyBytes)) != vectors \(hex(expectedKey))")
    }
    print("ok       hkdf_sha256_matches_the_published_key")

    guard let vectors = root["vectors"] as? [[String: Any]], !vectors.isEmpty else {
        throw fail("no vectors")
    }

    var seen = Set<String>()
    for vector in vectors {
        let name = try string(vector["name"], "name")
        seen.insert(name)
        let plaintext = Data(try string(vector["plaintext_utf8"], "plaintext_utf8").utf8)
        let nonceBytes = try data(hex: string(vector["nonce_hex"], "nonce_hex"))
        guard nonceBytes.count == 12 else { throw fail("\(name): nonce is not 12 bytes") }
        let expectedSealed = try b64urlDecode(string(vector["sealed_b64url"], "sealed_b64url"))
        let expectedLink = try string(vector["link"], "link")
        let expectedPlaintext = String(data: plaintext, encoding: .utf8) ?? ""

        let nonce = try ChaChaPoly.Nonce(data: nonceBytes)
        let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce, authenticating: aad)
        let sealed = nonceBytes + box.ciphertext + box.tag
        guard sealed == expectedSealed else {
            throw fail("\(name): sealed bytes differ (CryptoKit \(b64urlEncode(sealed)))")
        }
        guard prefix + b64urlEncode(sealed) == expectedLink else {
            throw fail("\(name): link differs")
        }
        guard expectedLink.lowercased().contains("smp") == false,
              expectedLink.lowercased().contains(".popopx.im") == false else {
            throw fail("\(name): link leaks a relay label")
        }
        guard !expectedLink.contains(expectedPlaintext) else {
            throw fail("\(name): link contains the plaintext URI")
        }
        print("ok       \(name): CryptoKit seal matches the published bytes")
        print("ok       \(name): link is \(expectedLink.count) characters and leaks no relay")

        guard expectedSealed.count > nonceBytes.count + 16 else {
            throw fail("\(name): sealed payload is too short")
        }
        let openBox = try ChaChaPoly.SealedBox(
            nonce: nonce,
            ciphertext: expectedSealed.dropFirst(12).dropLast(16),
            tag: expectedSealed.suffix(16)
        )
        let opened = try ChaChaPoly.open(openBox, using: key, authenticating: aad)
        guard opened == plaintext else { throw fail("\(name): opened bytes differ") }
        print("ok       \(name): CryptoKit opens the published ciphertext")

        var tampered = expectedSealed
        tampered[tampered.count - 1] ^= 0x01
        let tamperedBox = try ChaChaPoly.SealedBox(
            nonce: nonce,
            ciphertext: tampered.dropFirst(12).dropLast(16),
            tag: tampered.suffix(16)
        )
        do {
            _ = try ChaChaPoly.open(tamperedBox, using: key, authenticating: aad)
            throw fail("\(name): a flipped tag byte was accepted")
        } catch is CryptoKitError {
            print("ok       \(name): a flipped tag byte is rejected")
        }
    }

    guard seen.contains("contact") && seen.contains("channel") else {
        throw fail("vectors must cover both a contact and a channel URI")
    }
    print("PASS opaque invite v1: \(vectors.count) vectors, \(seen.count) URI kinds, CryptoKit agrees")
    return 0
}

let arguments = CommandLine.arguments
let path = arguments.count > 1 ? arguments[1] : "gateway/app/opaque_invite_vectors.json"
do {
    exit(Int32(try run(path: path)))
} catch {
    FileHandle.standardError.write(Data("FAIL \(error)\n".utf8))
    exit(1)
}