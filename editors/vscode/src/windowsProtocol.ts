// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — finite native worker frames

/**
 * Exchange bounded headers and exact binary payloads over owned process pipes.
 * Encode native integer identities without lossy JSON number conversion.
 * @module
 */

import type { NativeFileIdentity } from "./windowsResources.js";

/** Maximum bytes in one authored worker header. */
export const maximumHeaderBytes = 16384;

/** A complete bounded frame, retaining the exact following binary bytes. */
export interface WorkerFrame {
  /** Parsed finite JSON header, still requiring operation-specific checks. */
  readonly header: Record<string, unknown>;
  /** Exact payload bytes following the header. */
  readonly payload: Buffer;
}

/**
 * Require an ordinary JSON record from a private worker frame.
 * @param value - Untrusted parsed frame field.
 * @returns A record whose fields still require validation.
 */
export function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("native worker frame must contain a record");
  return value as Record<string, unknown>;
}

/**
 * Require one finite non-NUL protocol string.
 * @param value - Unknown frame field.
 * @returns Exact bounded string.
 */
export function textField(value: unknown): string {
  if (typeof value !== "string" || value.includes("\0") || value.length > 32767)
    throw new Error("native worker string is outside its bound");
  return value;
}

/**
 * Require a safely represented nonnegative integer within a caller's limit.
 * @param value - Unknown numeric frame field.
 * @param maximum - Inclusive finite ceiling.
 * @returns Validated integer.
 */
export function integerField(value: unknown, maximum = 67108864): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > maximum)
    throw new Error("native worker integer is outside its bound");
  return value;
}

/**
 * Encode one bounded JSON header and its exact payload.
 * @param header - Authored JSON fields, excluding reserved payload length.
 * @param payload - Exact finite binary payload.
 * @returns Complete length-prefixed frame.
 */
export function frame(header: Record<string, unknown>, payload: Buffer = Buffer.alloc(0)): Buffer {
  if (payload.length > 134217728) throw new Error("native worker payload exceeds its bound");
  const json = Buffer.from(JSON.stringify({ ...header, payloadBytes: payload.length }), "utf8");
  if (json.length > maximumHeaderBytes) throw new Error("native worker header exceeds its bound");
  const length = Buffer.alloc(4);
  length.writeUInt32LE(json.length);
  return Buffer.concat([length, json, payload]);
}

/**
 * Inspect a finite frame prefix without consuming an incomplete record.
 * @param bytes - Bytes observed on one private stream so far.
 * @returns Complete frame and consumed byte count, or undefined while incomplete.
 */
export function parseFrame(bytes: Buffer):
  | {
      /** Validated header and exact payload bytes for one complete frame. */
      value: WorkerFrame;
      /** Byte count consumed by this frame, preserving any following frame bytes. */
      consumed: number;
    }
  | undefined {
  if (bytes.length < 4) return undefined;
  const size = bytes.readUInt32LE(0);
  if (size < 2 || size > maximumHeaderBytes) throw new Error("native worker header is invalid");
  if (bytes.length < 4 + size) return undefined;
  const header = record(
    JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(4, 4 + size))),
  );
  const payloadBytes = integerField(header["payloadBytes"], 134217728);
  const consumed = 4 + size + payloadBytes;
  if (bytes.length < consumed) return undefined;
  return { value: { header, payload: bytes.subarray(4 + size, consumed) }, consumed };
}

/**
 * Serialize exact native metadata for the controller's independent guard comparison.
 * @param identity - Actual retained-handle metadata.
 * @returns Lossless JSON-compatible fields.
 */
export function identityRecord(identity: NativeFileIdentity): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(identity).map(([key, value]) => [
      key,
      typeof value === "bigint" ? value.toString() : value,
    ]),
  );
}

/**
 * Decode exact native metadata from an independently validated worker receipt.
 * @param value - Unknown JSON identity record.
 * @returns Exact native metadata without accepting fractional or oversized values.
 */
export function parseIdentity(value: unknown): NativeFileIdentity {
  const data = record(value);
  /**
   * Decode one unsigned 64-bit native integer represented in decimal.
   * @param key - Required metadata field name.
   * @returns Exact unsigned native value.
   */
  const wide = (key: string): bigint => {
    const encoded = textField(data[key]);
    if (!/^(?:0|[1-9][0-9]{0,19})$/.test(encoded))
      throw new Error("native identity integer is invalid");
    const decoded = BigInt(encoded);
    if (decoded > 0xffffffffffffffffn) throw new Error("native identity integer exceeds 64 bits");
    return decoded;
  };
  return {
    volume: integerField(data["volume"], 0xffffffff),
    fileId: wide("fileId"),
    attributes: integerField(data["attributes"], 0xffffffff),
    links: integerField(data["links"], 0xffffffff),
    size: wide("size"),
    written: wide("written"),
    created: wide("created"),
  };
}
