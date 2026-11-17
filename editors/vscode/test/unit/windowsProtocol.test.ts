// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — bounded worker protocol contracts

/**
 * Exercise frame boundaries, incremental consumption and exact integer serialization.
 * These are protocol input examples, not native file identities or scanner evidence.
 * @module
 */

import assert from "node:assert/strict";
import test from "node:test";
import {
  frame,
  identityRecord,
  integerField,
  maximumHeaderBytes,
  parseFrame,
  parseIdentity,
  record,
  textField,
} from "../../src/windowsProtocol.js";
import type { NativeFileIdentity } from "../../src/windowsResources.js";

/**
 * Prefix authored malformed JSON bytes without bypassing the production frame parser.
 * @param json - Actual header bytes supplied as the protocol input.
 * @returns A real byte buffer with its exact little-endian length prefix.
 */
function headerBytes(json: Buffer): Buffer {
  const size = Buffer.alloc(4);
  size.writeUInt32LE(json.length);
  return Buffer.concat([size, json]);
}

void test("record and scalar fields preserve valid boundary values", () => {
  const input = { owned: true };
  assert.equal(record(input), input);
  for (const value of [null, [], "record", 1, false, undefined])
    assert.throws(() => record(value), /must contain a record/u);
  assert.equal(textField(""), "");
  assert.equal(textField("x".repeat(32767)).length, 32767);
  for (const value of [1, null, "a\0b", "x".repeat(32768)])
    assert.throws(() => textField(value), /string is outside/u);
  assert.equal(integerField(0), 0);
  assert.equal(integerField(67108864), 67108864);
  assert.equal(integerField(5, 5), 5);
  for (const value of ["1", null, 1n, 0.5, NaN, Infinity, -1, 67108865])
    assert.throws(() => integerField(value), /integer is outside/u);
  assert.throws(() => integerField(6, 5), /integer is outside/u);
});

void test("binary frames wait for every prefix and consume only their own bytes", () => {
  const payload = Buffer.from([0, 255, 13, 10, 195, 40]);
  const encoded = frame({ operation: "read", payloadBytes: 999 }, payload);
  for (let size = 0; size < encoded.length; size += 1)
    assert.equal(parseFrame(encoded.subarray(0, size)), undefined);
  const next = frame({ operation: "next" });
  const parsed = parseFrame(Buffer.concat([encoded, next]));
  assert.ok(parsed);
  assert.equal(parsed.consumed, encoded.length);
  assert.deepEqual(parsed.value.header, { operation: "read", payloadBytes: payload.length });
  assert.deepEqual(parsed.value.payload, payload);
  const following = parseFrame(next);
  assert.ok(following);
  assert.deepEqual(following.value.header, { operation: "next", payloadBytes: 0 });
  assert.equal(following.value.payload.length, 0);
});

void test("authored frames enforce the exact header and payload byte ceilings", () => {
  const overhead = frame({ padding: "" }).readUInt32LE();
  const exact = frame({ padding: "x".repeat(maximumHeaderBytes - overhead) });
  assert.equal(exact.readUInt32LE(), maximumHeaderBytes);
  assert.ok(parseFrame(exact));
  assert.throws(
    () => frame({ padding: "x".repeat(maximumHeaderBytes - overhead + 1) }),
    /header exceeds/u,
  );
  assert.throws(() => frame({}, Buffer.alloc(134217729)), /payload exceeds/u);
});

void test("received frames refuse invalid lengths, UTF-8, JSON and envelope fields", () => {
  for (const size of [0, 1, maximumHeaderBytes + 1]) {
    const encoded = Buffer.alloc(4);
    encoded.writeUInt32LE(size);
    assert.throws(() => parseFrame(encoded), /header is invalid/u);
  }
  assert.throws(() => parseFrame(headerBytes(Buffer.from([195, 40]))), /encoded data/u);
  assert.throws(() => parseFrame(headerBytes(Buffer.from("{]"))), SyntaxError);
  assert.throws(() => parseFrame(headerBytes(Buffer.from("[]"))), /must contain a record/u);
  assert.throws(() => parseFrame(headerBytes(Buffer.from("{}"))), /integer is outside/u);
  assert.throws(
    () => parseFrame(headerBytes(Buffer.from('{"payloadBytes":134217729}'))),
    /integer is outside/u,
  );
});

const identity: NativeFileIdentity = {
  volume: 0xffffffff,
  fileId: 0xffffffffffffffffn,
  attributes: 0,
  links: 1,
  size: 0n,
  written: 9007199254740993n,
  created: 0n,
};

void test("native integer serialization round-trips zero and the full uint64 range", () => {
  const serialized = identityRecord(identity);
  assert.equal(serialized["fileId"], "18446744073709551615");
  assert.equal(serialized["written"], "9007199254740993");
  assert.equal(serialized["size"], "0");
  assert.equal(serialized["volume"], 0xffffffff);
  assert.deepEqual(parseIdentity(JSON.parse(JSON.stringify(serialized))), identity);
});

void test("native identity input refuses malformed decimal and overflowing fields", () => {
  const serialized = identityRecord(identity);
  for (const encoded of ["", "-1", "01", "1.2", "1e1", "not-decimal", "1".repeat(21)])
    assert.throws(() => parseIdentity({ ...serialized, fileId: encoded }), /integer is invalid/u);
  assert.throws(
    () => parseIdentity({ ...serialized, fileId: "18446744073709551616" }),
    /exceeds 64 bits/u,
  );
  assert.throws(() => parseIdentity({ ...serialized, size: 1 }), /string is outside/u);
  assert.throws(
    () => parseIdentity({ ...serialized, volume: 0x100000000 }),
    /integer is outside/u,
  );
});
