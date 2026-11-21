// Copyright (c) 2026 POPOPX (popopx.chat)
// SPDX-License-Identifier: AGPL-3.0-only

// POPOPX Service Suite — cross-implementation crypto oracle.
//
// WHY THIS FILE EXISTS
//
// gateway/app/crypto_service.py can prove to itself that it seals, signs and opens
// consistently, and it can do that forever without a phone in the room. What it
// cannot prove is the claim the whole suite rests on: that a POPOPX iOS client reads
// these bytes. The client's half of this protocol is
// apps/ios/Shared/Features/ServiceAccount/ChannelKeyRotationManager.swift, and that
// file calls CryptoKit — `ChaChaPoly.seal` / `ChaChaPoly.open` /
// `Curve25519.Signing` — with the envelope's `ciphertext` spelled ct ‖ tag (:234-251)
// and the AAD rebuilt from the caller's channel id (:229-231).
//
// CryptoKit is a system framework, so this oracle needs no packages and no network:
// it is the client's primitive, on the client's platform, run against the gateway's
// bytes and then the other way round. Agreement is measured, not assumed.
//
// BUILD AND RUN (macOS; `swiftc` ships with the Command Line Tools)
//
//   swiftc -O -o /tmp/oracle official_tools/swift_crypto_oracle.swift
//   /tmp/oracle selfcheck
//
//   # Python seals, CryptoKit opens: the direction a member's phone reads.
//   (cd gateway && python3 -m app.crypto_service emit /tmp/py.json)
//   /tmp/oracle verify /tmp/py.json
//
//   # CryptoKit seals, Python opens: the request direction of a key rotation.
//   /tmp/oracle seal --out /tmp/sw.json
//   (cd gateway && python3 -m app.crypto_service open /tmp/sw.json)
//
//   # Both must refuse a forgery. `aad` is the interesting mode: that envelope
//   # carries a valid signature, so a refusal there is the only evidence that the AAD
//   # is doing work rather than riding along.
//   /tmp/oracle verify /tmp/py.json --tamper aad
//   (cd gateway && python3 -m app.crypto_service open /tmp/py.json --tamper aad)
//
// A fixture's keys are drawn fresh per run. The identity private key is never
// serialised: the AAD forgery is built in memory and recorded already finished.

import CryptoKit
import Foundation

// ─────────────────────────────────────────────────────────────────────────────
// The protocol, as the client states it. Every constant here is a citation.
// ─────────────────────────────────────────────────────────────────────────────

enum Envelope {
    /// ChannelKeyRotationManager.swift:68, and crypto_service.py:93.
    static let protocolName = "popopx.channel.enc.v1"
    /// The `|` between the fields of the AAD and of the preimage (:134-157).
    static let separator: UInt8 = 0x7C
    static let nonceBytes = 12
    static let tagBytes = 16
    static let epochKeyBytes = 32
    static let identityKeyBytes = 32
    static let signatureBytes = 64
    /// `PopopxEcoLimits.maximumEpoch`.
    static let maximumEpoch = 1_000_000
    /// The channel an AAD forgery is sealed for instead of the real one.
    static let forgeryChannel = "ch-a-different-channel"
}

// ─────────────────────────────────────────────────────────────────────────────
// Reporting
// ─────────────────────────────────────────────────────────────────────────────

struct EcoFixtureError: Error {
    let message: String
    init(_ message: String) { self.message = message }
}

struct Report {
    var passed = 0
    var failures: [String] = []

    mutating func expect(_ name: String, _ condition: Bool, _ detail: String = "") {
        if condition {
            passed += 1
            print("PASS \(name)")
        } else {
            failures.append(name)
            print("FAIL \(name)\(detail.isEmpty ? "" : " — \(detail)")")
        }
    }

    func finish(_ context: String) -> Int32 {
        if failures.isEmpty {
            print("\(context): \(passed) checks passed, the two implementations agree")
            return 0
        }
        print("\(context): \(failures.count) FAILED of \(passed + failures.count) — \(failures.joined(separator: ", "))")
        return 1
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte-level mirrors of the client's derivations
// ─────────────────────────────────────────────────────────────────────────────

func joined(_ parts: [Data]) -> Data {
    var out = Data()
    for (index, part) in parts.enumerated() {
        if index > 0 { out.append(Envelope.separator) }
        out.append(part)
    }
    return out
}

/// `PopopxChannelEnvelope.authenticationData` (:134-143).
func authenticationData(channelId: String, epoch: Int, identityKey: Data) -> Data {
    joined([Data(Envelope.protocolName.utf8), Data(channelId.utf8), Data(String(epoch).utf8), identityKey])
}

/// `PopopxChannelEnvelope.signingPreimage` (:146-157) — raw bytes, never base64.
func signingPreimage(channelId: String, epoch: Int, nonce: Data, ciphertextWithTag: Data) -> Data {
    joined([Data(Envelope.protocolName.utf8), Data(channelId.utf8), Data(String(epoch).utf8), nonce, ciphertextWithTag])
}

func base64(_ data: Data) -> String { data.base64EncodedString() }

/// Standard padded base64, the alphabet the envelope's three byte fields use (:70).
func decoded(_ text: String?) -> Data? {
    guard let text else { return nil }
    return Data(base64Encoded: text)
}

func randomBytes(_ count: Int) -> Data {
    var data = Data(count: count)
    data.withUnsafeMutableBytes { raw in
        if let base = raw.baseAddress { _ = SecRandomCopyBytes(kSecRandomDefault, count, base) }
    }
    return data
}

func flippedFirstByte(_ text: String?) -> String? {
    guard var bytes = decoded(text), let first = bytes.first else { return nil }
    bytes[bytes.startIndex] = first ^ 0x01
    return base64(bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// The fixture file: the whole interface between the two implementations
// ─────────────────────────────────────────────────────────────────────────────

/// An envelope as it is on the wire. `epoch` stays a JSON number — the client encodes
/// it as an Int (:116-127), and a string here would be a different document that the
/// other implementation is entitled to refuse.
struct WireEnvelope {
    var epoch: Int
    var nonce: String
    var ciphertext: String
    var signature: String

    var json: [String: Any] {
        ["protocol": Envelope.protocolName, "epoch": epoch,
         "nonce": nonce, "ciphertext": ciphertext, "signature": signature]
    }

    init(epoch: Int, nonce: Data, ciphertextWithTag: Data, signature: Data) {
        self.epoch = epoch
        self.nonce = base64(nonce)
        self.ciphertext = base64(ciphertextWithTag)
        self.signature = base64(signature)
    }

    init?(json: [String: Any]?) {
        guard let json,
              let nonce = json["nonce"] as? String,
              let ciphertext = json["ciphertext"] as? String,
              let signature = json["signature"] as? String,
              (json["protocol"] as? String) == Envelope.protocolName else { return nil }
        // Numbers arrive as NSNumber from JSONSerialization; `epoch` is also carried
        // at the top level of the fixture, and the two must say the same thing.
        self.epoch = (json["epoch"] as? Int) ?? ((json["epoch"] as? NSNumber)?.intValue ?? 0)
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.signature = signature
    }

    func withSignature(_ text: String) -> WireEnvelope {
        var copy = self
        copy.signature = text
        return copy
    }

    func withCiphertext(_ text: String) -> WireEnvelope {
        var copy = self
        copy.ciphertext = text
        return copy
    }
}

struct Fixture {
    var channelId: String
    var epoch: Int
    var plaintext: Data
    var identityPublic: Data
    var epochKey: Data
    var envelope: WireEnvelope
    var forgeryAAD: WireEnvelope?
    var aad: Data?
    var preimage: Data?
    var sealedBy: String

    static let requiredKeys = ["channel_id", "epoch", "plaintext", "identity_public", "epoch_key", "envelope"]

    /// The memberwise initialiser, spelled out because the decoding `init` below
    /// suppresses the one Swift would otherwise give this struct.
    init(channelId: String, epoch: Int, plaintext: Data, identityPublic: Data, epochKey: Data,
         envelope: WireEnvelope, forgeryAAD: WireEnvelope?, aad: Data?, preimage: Data?, sealedBy: String) {
        self.channelId = channelId
        self.epoch = epoch
        self.plaintext = plaintext
        self.identityPublic = identityPublic
        self.epochKey = epochKey
        self.envelope = envelope
        self.forgeryAAD = forgeryAAD
        self.aad = aad
        self.preimage = preimage
        self.sealedBy = sealedBy
    }

    init(_ json: [String: Any]) throws {
        let absent = Fixture.requiredKeys.filter { json[$0] == nil }
        guard absent.isEmpty,
              let channelId = json["channel_id"] as? String,
              let epoch = json["epoch"] as? Int,
              let plaintext = decoded(json["plaintext"] as? String),
              let identityPublic = decoded(json["identity_public"] as? String),
              let epochKey = decoded(json["epoch_key"] as? String),
              let envelope = WireEnvelope(json: json["envelope"] as? [String: Any]) else {
            throw EcoFixtureError(absent.isEmpty
                ? "fixture fields are present but unreadable: \(json.keys.sorted())"
                : "fixture is missing \(absent.joined(separator: ", "))")
        }
        self.channelId = channelId
        self.epoch = epoch
        self.plaintext = plaintext
        self.identityPublic = identityPublic
        self.epochKey = epochKey
        self.envelope = envelope
        self.forgeryAAD = WireEnvelope(json: json["forgery_aad"] as? [String: Any])
        self.aad = decoded(json["aad"] as? String)
        self.preimage = decoded(json["preimage"] as? String)
        self.sealedBy = (json["sealed_by"] as? String) ?? "unknown"
    }

    var json: [String: Any] {
        var out: [String: Any] = [
            "channel_id": channelId,
            "epoch": epoch,
            "plaintext": base64(plaintext),
            "identity_public": base64(identityPublic),
            "epoch_key": base64(epochKey),
            "envelope": envelope.json,
            "sealed_by": sealedBy,
        ]
        // Written only because the peer needs the bytes to compare against. A fixture
        // without them still opens; it just proves less.
        if let aad { out["aad"] = base64(aad) }
        if let preimage { out["preimage"] = base64(preimage) }
        if let forgeryAAD { out["forgery_aad"] = forgeryAAD.json }
        return out
    }
}

func loadFixture(at path: String) throws -> Fixture {
    guard let data = FileManager.default.contents(atPath: path) else {
        throw EcoFixtureError("no fixture at \(path)")
    }
    guard let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
        throw EcoFixtureError("\(path) is not a JSON object")
    }
    return try Fixture(json)
}

// ─────────────────────────────────────────────────────────────────────────────
// Seal / open, mirroring the client
// ─────────────────────────────────────────────────────────────────────────────

struct Sealed {
    var nonce: Data
    var ciphertextWithTag: Data
    var signature: Data
}

/// `PopopxChannelEnvelope.seal` (:171-204). `privateSeed` is the raw 32-byte Ed25519
/// key, which is how the client's own test target reaches this path without a server.
func seal(
    plaintext: Data,
    epoch: Int,
    channelId: String,
    epochKey: Data,
    privateSeed: Data,
    aadChannelId: String? = nil
) -> Sealed? {
    guard let signer = try? Curve25519.Signing.PrivateKey(rawRepresentation: privateSeed) else { return nil }
    let nonceData = randomBytes(Envelope.nonceBytes)
    guard let nonce = try? ChaChaPoly.Nonce(data: nonceData) else { return nil }
    let box = try? ChaChaPoly.seal(
        plaintext,
        using: SymmetricKey(data: epochKey),
        nonce: nonce,
        authenticating: authenticationData(channelId: aadChannelId ?? channelId, epoch: epoch,
                                          identityKey: signer.publicKey.rawRepresentation)
    )
    guard let box else { return nil }
    // `ciphertext` on the wire is ct ‖ tag (:196-198). `combined` would put the nonce
    // in front of it and the client's `dropLast(16)` would then cut the wrong bytes.
    let ciphertextWithTag = box.ciphertext + box.tag
    guard let signature = try? signer.signature(for: signingPreimage(channelId: channelId, epoch: epoch,
                                                                     nonce: nonceData,
                                                                     ciphertextWithTag: ciphertextWithTag)) else { return nil }
    return Sealed(nonce: nonceData, ciphertextWithTag: ciphertextWithTag, signature: Data(signature))
}

/// Verify first, then decrypt — the order the client documents (:215, :221-251), and
/// the reason a forged frame never reaches the cipher. Any refusal answers nil.
func open(envelope: WireEnvelope, epoch: Int, channelId: String, epochKey: Data, identityPublic: Data) -> Data? {
    guard let nonce = decoded(envelope.nonce),
          let ciphertext = decoded(envelope.ciphertext),
          let signature = decoded(envelope.signature),
          nonce.count == Envelope.nonceBytes,
          signature.count == Envelope.signatureBytes,
          ciphertext.count > Envelope.tagBytes,
          identityPublic.count == Envelope.identityKeyBytes,
          epochKey.count == Envelope.epochKeyBytes else { return nil }
    guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: identityPublic),
          key.isValidSignature(signature, for: signingPreimage(channelId: channelId, epoch: epoch,
                                                               nonce: nonce, ciphertextWithTag: ciphertext)) else { return nil }
    // `SealedBox(combined:)` is deliberately not used: the envelope keeps `nonce` as
    // its own field, so the box is re-assembled from ct ‖ tag.
    guard let sealNonce = try? ChaChaPoly.Nonce(data: nonce),
          let box = try? ChaChaPoly.SealedBox(nonce: sealNonce,
                                              ciphertext: ciphertext.dropLast(Envelope.tagBytes),
                                              tag: ciphertext.suffix(Envelope.tagBytes)) else { return nil }
    return try? ChaChaPoly.open(box, using: SymmetricKey(data: epochKey),
                                authenticating: authenticationData(channelId: channelId, epoch: epoch,
                                                                   identityKey: identityPublic))
}

// ─────────────────────────────────────────────────────────────────────────────
// Commands
// ─────────────────────────────────────────────────────────────────────────────

func selfcheck(_ report: inout Report) {
    let key = SymmetricKey(data: randomBytes(Envelope.epochKeyBytes))
    let nonceBytes = randomBytes(Envelope.nonceBytes)
    guard let nonce = try? ChaChaPoly.Nonce(data: nonceBytes) else {
        report.expect("chachapoly_accepts_a_96_bit_nonce", false)
        return
    }
    report.expect("chachapoly_accepts_a_96_bit_nonce", nonce.withUnsafeBytes { Data($0) } == nonceBytes)
    let message = Data("popopx oracle".utf8)
    guard let box = try? ChaChaPoly.seal(message, using: key, nonce: nonce, authenticating: Data("aad".utf8)) else {
        report.expect("chachapoly_seals", false)
        return
    }
    report.expect("chachapoly_tag_is_16_bytes", box.tag.count == Envelope.tagBytes)
    report.expect("chachapoly_ciphertext_is_stream_length", box.ciphertext.count == message.count)
    let wire = box.ciphertext + box.tag
    var rebuilt: Data?
    if let split = try? ChaChaPoly.SealedBox(nonce: nonce, ciphertext: wire.dropLast(Envelope.tagBytes),
                                             tag: wire.suffix(Envelope.tagBytes)) {
        rebuilt = try? ChaChaPoly.open(split, using: key, authenticating: Data("aad".utf8))
    }
    report.expect("ct_tag_spelling_reassembles", rebuilt == message)
    var refused = false
    if let split = try? ChaChaPoly.SealedBox(nonce: nonce, ciphertext: wire.dropLast(Envelope.tagBytes),
                                             tag: wire.suffix(Envelope.tagBytes)) {
        refused = (try? ChaChaPoly.open(split, using: key, authenticating: Data("aaB".utf8))) == nil
    }
    report.expect("aad_mismatch_is_refused", refused)
    let signer = Curve25519.Signing.PrivateKey()
    let preimage = Data("the signed bytes".utf8)
    guard let signature = try? signer.signature(for: preimage) else {
        report.expect("ed25519_signs", false)
        return
    }
    report.expect("ed25519_signature_is_64_raw_bytes", signature.count == Envelope.signatureBytes)
    report.expect("ed25519_public_is_32_raw_bytes", signer.publicKey.rawRepresentation.count == Envelope.identityKeyBytes)
    report.expect("signature_verifies", signer.publicKey.isValidSignature(signature, for: preimage))
    report.expect("signature_over_other_bytes_is_refused",
                  !signer.publicKey.isValidSignature(signature, for: Data("the signed byte".utf8)))
    report.expect("nonce_and_epoch_are_the_whole_aad_layout",
                  authenticationData(channelId: "ch", epoch: 2, identityKey: Data()).count
                      == Envelope.protocolName.utf8.count + 1 + 2 + 1 + 1 + 1)
}

func verify(_ fixture: Fixture, tamper: String, _ report: inout Report) {
    var envelope = fixture.envelope
    switch tamper {
    case "none":
        break
    case "signature":
        guard let mutated = flippedFirstByte(envelope.signature) else {
            report.expect("signature_is_tamperable", false, "signature field did not decode")
            return
        }
        envelope = envelope.withSignature(mutated)
    case "ciphertext":
        guard let mutated = flippedFirstByte(envelope.ciphertext) else {
            report.expect("ciphertext_is_tamperable", false, "ciphertext field did not decode")
            return
        }
        envelope = envelope.withCiphertext(mutated)
    case "aad":
        guard let forgery = fixture.forgeryAAD else {
            report.expect("fixture_carries_an_aad_forgery", false, "no forgery_aad in the fixture")
            return
        }
        envelope = forgery
    default:
        report.expect("known_tamper_mode", false, "no such mode \(tamper)")
        return
    }
    report.expect("frame_epoch_is_the_fixtures_epoch", envelope.epoch == fixture.epoch,
                  "frame says \(envelope.epoch), fixture says \(fixture.epoch)")
    let opened = open(envelope: envelope, epoch: fixture.epoch, channelId: fixture.channelId,
                      epochKey: fixture.epochKey, identityPublic: fixture.identityPublic)
    guard tamper == "none" else {
        report.expect("refuses_\(tamper)_forgery", opened == nil, "the forged envelope opened")
        return
    }
    report.expect("chachapoly_opens_the_peers_envelope", opened == fixture.plaintext,
                  "opened \(opened?.count ?? -1) bytes, fixture declares \(fixture.plaintext.count)")
    // The derivations are compared byte for byte rather than trusted. A tag can only
    // pass when both ends used the same AAD, so agreement on the *bytes* is what
    // separates "both implementations work" from "both implementations are wrong the
    // same way" — and the second case is the one that ships.
    let ourAAD = authenticationData(channelId: fixture.channelId, epoch: fixture.epoch, identityKey: fixture.identityPublic)
    let ourPreimage = signingPreimage(channelId: fixture.channelId, epoch: fixture.epoch,
                                      nonce: decoded(envelope.nonce) ?? Data(),
                                      ciphertextWithTag: decoded(envelope.ciphertext) ?? Data())
    report.expect("aad_bytes_agree", fixture.aad == nil || fixture.aad == ourAAD,
                  "CryptoKit \(base64(ourAAD)) vs peer \(fixture.aad.map(base64) ?? "-")")
    report.expect("preimage_bytes_agree", fixture.preimage == nil || fixture.preimage == ourPreimage,
                  "CryptoKit \(base64(ourPreimage)) vs peer \(fixture.preimage.map(base64) ?? "-")")
    report.expect("identity_key_is_raw_32", fixture.identityPublic.count == Envelope.identityKeyBytes)
    report.expect("epoch_key_is_raw_32", fixture.epochKey.count == Envelope.epochKeyBytes)
    report.expect("nonce_is_raw_12", (decoded(envelope.nonce) ?? Data()).count == Envelope.nonceBytes)
    report.expect("signature_is_raw_64", (decoded(envelope.signature) ?? Data()).count == Envelope.signatureBytes)
    report.expect("ciphertext_carries_an_appended_tag",
                  (decoded(envelope.ciphertext) ?? Data()).count > Envelope.tagBytes)
}

func sealFixture(channelId: String, epoch: Int, plaintextText: String, outPath: String, _ report: inout Report) {
    let privateSeed = randomBytes(Envelope.identityKeyBytes)
    let epochKey = randomBytes(Envelope.epochKeyBytes)
    let plaintext = Data(plaintextText.utf8)
    guard let identityPublic = try? Curve25519.Signing.PrivateKey(rawRepresentation: privateSeed).publicKey.rawRepresentation else {
        report.expect("identity_seed_is_a_raw_32_byte_key", false, "\(privateSeed.count) bytes")
        return
    }
    guard let sealed = seal(plaintext: plaintext, epoch: epoch, channelId: channelId,
                            epochKey: epochKey, privateSeed: privateSeed) else {
        report.expect("chachapoly_sealed_a_fixture", false, "CryptoKit refused to seal")
        return
    }
    guard let forgery = seal(plaintext: plaintext, epoch: epoch, channelId: channelId, epochKey: epochKey,
                             privateSeed: privateSeed, aadChannelId: Envelope.forgeryChannel) else {
        report.expect("aad_forgery_sealed", false, "CryptoKit refused to seal the foreign AAD")
        return
    }
    let envelope = WireEnvelope(epoch: epoch, nonce: sealed.nonce,
                                ciphertextWithTag: sealed.ciphertextWithTag, signature: sealed.signature)
    let forgeryEnvelope = WireEnvelope(epoch: epoch, nonce: forgery.nonce,
                                       ciphertextWithTag: forgery.ciphertextWithTag, signature: forgery.signature)
    report.expect("own_envelope_opens",
                  open(envelope: envelope, epoch: epoch, channelId: channelId,
                       epochKey: epochKey, identityPublic: identityPublic) == plaintext)
    report.expect("own_aad_forgery_is_refused",
                  open(envelope: forgeryEnvelope, epoch: epoch, channelId: channelId,
                       epochKey: epochKey, identityPublic: identityPublic) == nil)
    report.expect("own_signature_forgery_is_refused",
                  open(envelope: envelope.withSignature(base64(randomBytes(Envelope.signatureBytes))),
                       epoch: epoch, channelId: channelId, epochKey: epochKey,
                       identityPublic: identityPublic) == nil)
    let fixture = Fixture(channelId: channelId, epoch: epoch, plaintext: plaintext, identityPublic: identityPublic,
                          epochKey: epochKey, envelope: envelope, forgeryAAD: forgeryEnvelope,
                          aad: authenticationData(channelId: channelId, epoch: epoch, identityKey: identityPublic),
                          preimage: signingPreimage(channelId: channelId, epoch: epoch, nonce: sealed.nonce,
                                                    ciphertextWithTag: sealed.ciphertextWithTag),
                          sealedBy: "swift oracle (CryptoKit)")
    guard let data = try? JSONSerialization.data(withJSONObject: fixture.json, options: [.prettyPrinted, .sortedKeys]),
          let text = String(data: data, encoding: .utf8) else {
        report.expect("fixture_serialises", false, "JSON writing failed")
        return
    }
    do {
        try (text + "\n").write(toFile: outPath, atomically: true, encoding: .utf8)
        report.expect("fixture_written", FileManager.default.fileExists(atPath: outPath), outPath)
        print("emitted \(outPath) (sealed by \(fixture.sealedBy))")
    } catch {
        report.expect("fixture_written", false, "\(error)")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

func optionValue(_ arguments: [String], _ flag: String, _ fallback: String) -> String {
    guard let index = arguments.firstIndex(of: flag), index + 1 < arguments.count else { return fallback }
    return arguments[index + 1]
}

func run(_ arguments: [String]) -> Int32 {
    guard let command = arguments.first else {
        print("""
        usage: swift_crypto_oracle selfcheck
               swift_crypto_oracle verify <fixture.json> [--tamper none|signature|ciphertext|aad]
               swift_crypto_oracle seal --out <fixture.json> [--channel ID] [--epoch N] [--plaintext TEXT]
        """)
        return 2
    }
    let rest = Array(arguments.dropFirst())
    var report = Report()
    switch command {
    case "selfcheck":
        selfcheck(&report)
        return report.finish("selfcheck")
    case "verify":
        guard let path = rest.first(where: { !$0.hasPrefix("--") }) else {
            print("verify needs a fixture path")
            return 2
        }
        do {
            verify(try loadFixture(at: path), tamper: optionValue(rest, "--tamper", "none"), &report)
            return report.finish("\(path) via CryptoKit [tamper=\(optionValue(rest, "--tamper", "none"))]")
        } catch let error as EcoFixtureError {
            print("fixture error: \(error.message)")
            return 1
        } catch {
            print("fixture error: \(error)")
            return 1
        }
    case "seal":
        let epochText = optionValue(rest, "--epoch", "2")
        guard let epoch = Int(epochText), (1...Envelope.maximumEpoch).contains(epoch) else {
            print("--epoch must be an integer in 1...\(Envelope.maximumEpoch), got \(epochText)")
            return 2
        }
        sealFixture(channelId: optionValue(rest, "--channel", "ch-cross-check"),
                    epoch: epoch,
                    plaintextText: optionValue(rest, "--plaintext",
                                               "{\"epoch\":3,\"keyBase64URL\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}"),
                    outPath: optionValue(rest, "--out", "/tmp/sw.json"), &report)
        return report.finish("seal")
    default:
        print("unknown command \(command)")
        return 2
    }
}

exit(run(Array(CommandLine.arguments.dropFirst())))
