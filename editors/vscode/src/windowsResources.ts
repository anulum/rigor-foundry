// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — owned native NTFS resources

/**
 * Retain local NTFS parent chains and operate on exact no-reparse child objects.
 * Read file bytes in the owned worker; the editor thread uses only bounded resource setup.
 * @module
 */

import path from "node:path";
import { createHash } from "node:crypto";
import * as abi from "./windowsAbi.js";

/** Immutable native file metadata, without synthesized POSIX mode or timestamps. */
export interface NativeFileIdentity {
  /** NTFS volume serial. */
  readonly volume: number;
  /** Exact native file index. */
  readonly fileId: bigint;
  /** Actual Win32 attributes. */
  readonly attributes: number;
  /** Current hard-link count. */
  readonly links: number;
  /** Exact file byte size. */
  readonly size: bigint;
  /** Exact last-write FILETIME. */
  readonly written: bigint;
  /** Exact creation FILETIME. */
  readonly created: bigint;
}

/** Refusal retaining the native numeric code without displaying untrusted path text. */
export class WindowsResourceError extends Error {
  /** Win32 error code, captured before any further native API call. */
  public readonly code: number;
  /**
   * Capture a native failure from an immediate API result.
   * @param operation - Authored operation name.
   * @param code - Actual saved Windows error or translated NTSTATUS.
   */
  public constructor(operation: string, code = abi.getLastError()) {
    super(`native Windows ${operation} failed (${String(code)})`);
    this.code = code;
  }
}

/**
 * Validate an actual non-NULL, non-invalid native handle.
 * @param value - Unknown native output.
 * @returns Exact owned handle address.
 * @throws {WindowsResourceError} If the native API returned no valid resource.
 */
export function requireHandle(value: unknown): bigint {
  const pointer = abi.nativePointer(value);
  if (pointer === null || pointer === 0n || pointer === -1n || pointer === 0xffffffffffffffffn) {
    throw new WindowsResourceError("handle acquisition");
  }
  return pointer;
}

/**
 * Require a plain decoded record before reading any ABI fields.
 * @param value - Unknown native structure conversion.
 * @returns Record whose individual fields still require validation.
 * @throws {Error} For an unexpected decoder representation.
 */
export function requireRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("native Windows structure has an unsupported representation");
  }
  return value as Record<string, unknown>;
}

/**
 * Validate one exact unsigned native integer.
 * @param value - Unknown DWORD or size conversion.
 * @param maximum - Inclusive bound admitted by the caller.
 * @returns Safely represented nonnegative integer.
 * @throws {Error} For a fractional, negative, oversized or mistyped native result.
 */
export function requireInteger(value: unknown, maximum = 0xffffffff): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new Error("native Windows integer is outside the admitted bound");
  }
  return value;
}

/**
 * Decode FILETIME without losing its high bits.
 * @param value - Native FILETIME record.
 * @returns Exact unsigned tick count.
 */
function fileTime(value: unknown): bigint {
  const fields = requireRecord(value);
  return (BigInt(requireInteger(fields["high"])) << 32n) | BigInt(requireInteger(fields["low"]));
}

/**
 * Read the actual metadata and reject a reparse or wrong-kind object.
 * @param handle - Caller-retained actual handle.
 * @param directory - Required object kind.
 * @returns Exact handle-bound identity and raw metadata.
 * @throws {Error} For inaccessible, non-disk, reparse or wrong-kind resources.
 */
function identity(handle: bigint, directory: boolean): NativeFileIdentity {
  const buffer = Buffer.alloc(abi.koffi.sizeof(abi.nativeTypes.fileInformation));
  if (abi.getFileInformation(handle, buffer) === 0)
    throw new WindowsResourceError("file identity");
  const data = requireRecord(abi.koffi.decode(buffer, abi.nativeTypes.fileInformation));
  const attributes = requireInteger(data["attributes"]);
  if (
    abi.getFileType(handle) !== 1 ||
    (attributes & 0x400) !== 0 ||
    Boolean(attributes & 0x10) !== directory
  ) {
    throw new Error("native Windows resource is not the required non-reparse disk object");
  }
  return {
    volume: requireInteger(data["volume"]),
    attributes,
    fileId:
      (BigInt(requireInteger(data["indexHigh"])) << 32n) |
      BigInt(requireInteger(data["indexLow"])),
    links: requireInteger(data["links"]),
    size:
      (BigInt(requireInteger(data["sizeHigh"])) << 32n) | BigInt(requireInteger(data["sizeLow"])),
    written: fileTime(data["written"]),
    created: fileTime(data["created"]),
  };
}

/**
 * Resolve an exact retained object to one complete native namespace string.
 * @param handle - Live file or directory.
 * @param flags - GUID-volume or NT-device namespace selector.
 * @returns Complete native string, with no permissive rewriting.
 */
export function nativePath(handle: bigint, flags = 1): string {
  const buffer = Buffer.alloc(65536);
  const length = abi.getFinalPath(handle, buffer, buffer.length / 2, flags);
  if (length === 0 || length >= buffer.length / 2) throw new WindowsResourceError("final path");
  return buffer.subarray(0, length * 2).toString("utf16le");
}

/**
 * Reject Win32 aliases and ambiguous child components before native lookup.
 * @param name - One literal component.
 * @throws {Error} For traversal, alternate streams, reserved devices or ambiguous suffixes.
 */
function component(name: string): void {
  for (const character of name) {
    if (character.charCodeAt(0) < 32)
      throw new Error("native Windows path has an ambiguous component");
  }
  if (
    !name ||
    name === "." ||
    name === ".." ||
    /[ .]$/.test(name) ||
    /[<>:"/\\|?*]/.test(name) ||
    /^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)/i.test(name)
  ) {
    throw new Error("native Windows path has an ambiguous component");
  }
}

/**
 * Convert the process token's user SID to an independently retained JavaScript string.
 * @returns Current process user SID.
 */
function currentUserSid(): string {
  const current = abi.nativePointer(abi.getCurrentProcess());
  if (current === null) throw new Error("current native process is unavailable");
  const output: unknown[] = [null];
  if (abi.openProcessToken(current, 8, output) === 0)
    throw new WindowsResourceError("process token");
  const token = requireHandle(output[0]);
  let string: bigint | undefined;
  try {
    const size = [0];
    if (abi.getTokenInformation(token, 1, null, 0, size) !== 0 || abi.getLastError() !== 122) {
      throw new Error("native token did not supply a required buffer size");
    }
    const bytes = requireInteger(size[0], 65536);
    if (bytes < 8) throw new Error("native token user buffer is too small");
    const buffer = Buffer.alloc(bytes);
    if (abi.getTokenInformation(token, 1, buffer, buffer.length, size) === 0)
      throw new WindowsResourceError("token user");
    const result: unknown[] = [null];
    if (abi.sidToString(buffer.readBigUInt64LE(0), result) === 0)
      throw new WindowsResourceError("user SID");
    string = requireHandle(result[0]);
    const sid = abi.koffi.decode.string16(string);
    if (!/^S-1-(?:\d+-)*\d+$/.test(sid)) throw new Error("native user SID is unsupported");
    return sid;
  } finally {
    if (string !== undefined) abi.localFree(string);
    abi.closeHandle(token);
  }
}

/**
 * Allocate a current-user owned protected DACL before an owned operation.
 * @param access - Full control for creation or read-only data access for validation guards.
 * @returns Owned descriptor that the caller must release using LocalFree.
 */
function securityDescriptor(access: "FA" | "FR"): bigint {
  const sid = currentUserSid();
  const result: unknown[] = [null];
  if (
    abi.stringToSecurityDescriptor(`O:${sid}D:P(A;;${access};;;${sid})`, 1, result, null) === 0
  ) {
    throw new WindowsResourceError("private security descriptor");
  }
  return requireHandle(result[0]);
}

/**
 * Open a native child directly relative to its retained parent.
 * @param parent - Live retained parent object.
 * @param name - One unambiguous component.
 * @param directory - Required object kind.
 * @param create - Exclusive creation instead of opening an existing object.
 * @param access - Explicit access rights for this resource's lifecycle.
 * @returns Owned child handle, already checked for object kind.
 */
function openRelative(
  parent: bigint,
  name: string,
  directory: boolean,
  create: boolean,
  access: number,
): bigint {
  component(name);
  const length = Buffer.byteLength(name, "utf16le");
  if (length > 65532) throw new Error("native child name exceeds the UTF-16 bound");
  const descriptor = create ? securityDescriptor("FA") : null;
  const result: unknown[] = [null];
  try {
    const status = abi.ntCreateFile(
      result,
      access,
      {
        length: abi.koffi.sizeof(abi.objectAttributesType),
        root: parent,
        name: { length, maximumLength: length + 2, buffer: name },
        attributes: 0x1040,
        security: descriptor,
        quality: null,
      },
      { status: null, information: 0 },
      null,
      directory ? 0x10 : 0x80,
      1,
      create ? 2 : 1,
      0x20 | 0x200000 | (directory ? 1 : 0x40) | (create && !directory ? 2 : 0),
      null,
      0,
    );
    if (status < 0)
      throw new WindowsResourceError("relative open", abi.ntStatusToDosError(status));
    const handle = requireHandle(result[0]);
    try {
      identity(handle, directory);
    } catch (error: unknown) {
      abi.closeHandle(handle);
      throw error;
    }
    return handle;
  } finally {
    if (descriptor !== null) abi.localFree(descriptor);
  }
}

/** Exact file object owned independently of its caller-retained parent chain. */
export class WindowsFile {
  /** Current native handle, absent only after release. */
  private resource: bigint | undefined;
  /**
   * Adopt one already checked file handle.
   * @param handle - Owned file resource transferred by WindowsDirectory.
   */
  public constructor(handle: bigint) {
    this.resource = handle;
  }
  /**
   * Live native handle, refusing operations after release.
   * @returns The exact live owned file handle.
   */
  public get handle(): bigint {
    if (this.resource === undefined) throw new Error("native Windows file is closed");
    return this.resource;
  }
  /**
   * Obtain exact native metadata from this file's retained handle.
   * @returns Raw native regular-file metadata.
   */
  public identity(): NativeFileIdentity {
    return identity(this.handle, false);
  }
  /**
   * Read exact bounded bytes and recheck metadata; call only in the owned worker.
   * @param maximumBytes - Hard size ceiling for the whole payload.
   * @returns Exact bytes from the retained file.
   */
  public read(maximumBytes: number): Buffer {
    const before = this.identity();
    if (before.links !== 1 || before.size > BigInt(maximumBytes))
      throw new Error("native evidence file exceeds its type, link or byte bound");
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const block = bytes.subarray(offset, Math.min(bytes.length, offset + 1048576));
      const count = [0];
      if (abi.readFile(this.handle, block, block.length, count, null) === 0)
        throw new WindowsResourceError("file read");
      const read = requireInteger(count[0], block.length);
      if (read === 0) throw new Error("native evidence file shortened during its read");
      offset += read;
    }
    const extra = [0];
    if (abi.readFile(this.handle, Buffer.alloc(1), 1, extra, null) === 0)
      throw new WindowsResourceError("file end check");
    if (extra[0] !== 0 || !sameIdentity(before, this.identity()))
      throw new Error("native evidence file changed during its read");
    return bytes;
  }
  /**
   * Write and flush exact owned bytes before switching to a read guard.
   * @param bytes - Complete finite payload.
   */
  public write(bytes: Buffer): void {
    let offset = 0;
    while (offset < bytes.length) {
      const block = bytes.subarray(offset, Math.min(bytes.length, offset + 1048576));
      const count = [0];
      if (abi.writeFile(this.handle, block, block.length, count, null) === 0)
        throw new WindowsResourceError("private input write");
      const written = requireInteger(count[0], block.length);
      if (written === 0) throw new Error("private input write made no progress");
      offset += written;
    }
    if (abi.flushFile(this.handle) === 0) throw new WindowsResourceError("private input flush");
  }
  /**
   * Set an explicit protected current-user DACL on this owned private input.
   * @param access - Read-only guard or full control for owned cleanup.
   */
  public permissions(access: "FR" | "FA"): void {
    const descriptor = securityDescriptor(access);
    try {
      if (abi.setObjectSecurity(this.handle, 0x80000004, descriptor) === 0)
        throw new WindowsResourceError("private input DACL");
    } finally {
      abi.localFree(descriptor);
    }
  }
  /** Mark this exact owned object for deletion when its handle is released. */
  public discard(): void {
    const information = Buffer.alloc(4);
    information.writeInt32LE(1);
    if (abi.setFileInformation(this.handle, 4, information, information.length) === 0)
      throw new WindowsResourceError("owned file discard");
  }
  /** Release the owned handle exactly once. */
  public close(): void {
    if (this.resource !== undefined) {
      const resource = this.resource;
      if (abi.closeHandle(resource) === 0) throw new WindowsResourceError("file close");
      this.resource = undefined;
    }
  }
}

/**
 * Compare exact file metadata without lossy conversion or path-stat substitution.
 * @param left - Metadata before the operation.
 * @param right - Metadata after the operation.
 * @returns Whether every stability field remains equal.
 */
export function sameIdentity(left: NativeFileIdentity, right: NativeFileIdentity): boolean {
  return (
    left.volume === right.volume &&
    left.fileId === right.fileId &&
    left.attributes === right.attributes &&
    left.links === right.links &&
    left.size === right.size &&
    left.written === right.written &&
    left.created === right.created
  );
}

/** Retained complete local NTFS directory chain with write/delete sharing denied. */
export class WindowsDirectory {
  /** Independently owned native directory handles from volume root through leaf. */
  private readonly handles: bigint[];
  /** Retained directory's native identity. */
  private readonly original: NativeFileIdentity;
  /** Exact GUID-volume spelling established through retained handles. */
  public readonly nativePath: string;
  /**
   * Adopt an internally checked owned directory chain.
   * @param handles - Full independently owned chain.
   * @param nativePath - Exact GUID spelling checked against the leaf.
   */
  private constructor(handles: bigint[], nativePath: string) {
    this.handles = handles;
    this.nativePath = nativePath;
    this.original = identity(this.handle, true);
  }
  /**
   * Live retained leaf handle.
   * @returns Exact live directory handle.
   */
  public get handle(): bigint {
    const handle = this.handles.at(-1);
    if (handle === undefined) throw new Error("native Windows directory is closed");
    return handle;
  }
  /**
   * Exact current leaf identity, checked against its original native object.
   * @returns Current handle-bound directory metadata.
   */
  public identity(): NativeFileIdentity {
    const current = identity(this.handle, true);
    if (current.volume !== this.original.volume || current.fileId !== this.original.fileId)
      throw new Error("native Windows directory identity changed");
    return current;
  }
  /**
   * Retain every component of an explicit fixed local NTFS directory.
   * @param absolute - Drive-absolute path without traversal, device or UNC spellings.
   * @returns Owned complete no-reparse chain.
   */
  public static open(absolute: string): WindowsDirectory {
    const parsed = path.win32.parse(absolute);
    if (!/^[A-Za-z]:[\\/]$/.test(parsed.root) || !path.win32.isAbsolute(absolute))
      throw new Error("native evidence requires a drive-absolute local path");
    const components = absolute
      .slice(parsed.root.length)
      .split(/[\\/]/)
      .filter((name) => name !== "");
    for (const name of components) component(name);
    if (abi.getDriveType(parsed.root) !== 3)
      throw new Error("native evidence requires a fixed local NTFS volume");
    const handles: bigint[] = [];
    try {
      handles.push(
        requireHandle(abi.createFile(parsed.root, 0x1000a1, 1, null, 3, 0x2200000, null)),
      );
      const first = handles[0];
      if (first === undefined) throw new Error("native root is unavailable");
      identity(first, true);
      let expected = nativePath(first);
      if (!/^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$/.test(expected))
        throw new Error("native root has no supported GUID namespace");
      for (const name of components) {
        const parent = handles.at(-1);
        if (parent === undefined) throw new Error("native parent is unavailable");
        const handle = openRelative(parent, name, true, false, 0x1000a1);
        handles.push(handle);
        expected = expected.replace(/\\$/, "") + "\\" + name;
        if (nativePath(handle).replace(/\\$/, "") !== expected.replace(/\\$/, ""))
          throw new Error("native directory name differs from its retained parent");
      }
      const leaf = handles.at(-1);
      if (leaf === undefined) throw new Error("native directory is unavailable");
      const filesystem = Buffer.alloc(128);
      if (abi.getVolumeInformation(leaf, null, 0, null, null, null, filesystem, 64) === 0)
        throw new WindowsResourceError("filesystem identity");
      if (filesystem.toString("utf16le").split("\0", 1)[0] !== "NTFS")
        throw new Error("native evidence requires NTFS");
      return new WindowsDirectory(handles, expected);
    } catch (error: unknown) {
      for (const handle of handles.reverse()) abi.closeHandle(handle);
      throw error;
    }
  }
  /**
   * Retain one no-reparse child directory with an independent owned parent chain.
   * @param name - One literal child component.
   * @param create - Atomically create a new protected current-user-owned directory.
   * @returns Independently owned complete chain.
   */
  public child(name: string, create = false): WindowsDirectory {
    this.identity();
    component(name);
    const current = abi.nativePointer(abi.getCurrentProcess());
    if (current === null) throw new Error("current native process is unavailable");
    const handles: bigint[] = [];
    try {
      for (const handle of this.handles) {
        const duplicate: unknown[] = [null];
        if (abi.duplicateHandle(current, handle, current, duplicate, 0, 0, 2) === 0)
          throw new WindowsResourceError("parent duplication");
        handles.push(requireHandle(duplicate[0]));
      }
      const handle = openRelative(this.handle, name, true, create, 0x1000a1);
      handles.push(handle);
      const expected = this.nativePath.replace(/\\$/, "") + "\\" + name;
      if (nativePath(handle).replace(/\\$/, "") !== expected)
        throw new Error("native child directory binding changed");
      return new WindowsDirectory(handles, expected);
    } catch (error: unknown) {
      for (const handle of handles.reverse()) abi.closeHandle(handle);
      throw error;
    }
  }
  /**
   * Retain an exact regular child, optionally creating one private writable object.
   * @param name - One literal child component.
   * @param create - Exclusive write-through creation, without overwrite.
   * @param cleanup - Open an owned object for discard, after read guards have closed.
   * @param changeAcl - Retain WRITE_DAC only for owned private-copy lifecycle transitions.
   * @returns Owned file; the caller retains this directory until that file closes.
   */
  public file(name: string, create = false, cleanup = false, changeAcl = false): WindowsFile {
    const parent = this.identity();
    const access =
      (0x80000000 |
        0x100000 |
        (create ? 0x40000000 | 0x50000 : 0) |
        (cleanup ? 0x10000 : 0) |
        (changeAcl ? 0x40000 : 0)) >>>
      0;
    const file = new WindowsFile(openRelative(this.handle, name, false, create, access));
    try {
      const current = file.identity();
      if (
        current.volume !== parent.volume ||
        nativePath(file.handle) !== this.nativePath.replace(/\\$/, "") + "\\" + name
      )
        throw new Error("native file differs from its retained parent and name");
      this.identity();
      return file;
    } catch (error: unknown) {
      try {
        if (create) file.discard();
      } finally {
        file.close();
      }
      throw error;
    }
  }
  /**
   * Discard one exact empty owned child directory after all child guards have closed.
   * @param name - Owned private directory's leaf name.
   * @param expected - Its previously captured native identity.
   */
  public discardChild(name: string, expected: NativeFileIdentity): void {
    this.identity();
    const handle = openRelative(this.handle, name, true, false, 0x1100a1);
    const failures: unknown[] = [];
    try {
      const current = identity(handle, true);
      if (current.volume !== expected.volume || current.fileId !== expected.fileId)
        throw new Error("owned private directory changed before cleanup");
      const information = Buffer.alloc(4);
      information.writeInt32LE(1);
      if (abi.setFileInformation(handle, 4, information, information.length) === 0)
        throw new WindowsResourceError("owned directory discard");
    } catch (error: unknown) {
      failures.push(error);
    }
    try {
      if (abi.closeHandle(handle) === 0)
        throw new WindowsResourceError("owned directory discard handle close");
    } catch (error: unknown) {
      failures.push(error);
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1)
      throw new AggregateError(failures, "native Windows directory discard and close failed");
  }
  /** Release every retained directory handle in reverse acquisition order. */
  public close(): void {
    const failures: unknown[] = [];
    for (const handle of [...this.handles].reverse()) {
      if (abi.closeHandle(handle) === 0)
        failures.push(new WindowsResourceError("directory close"));
      else this.handles.splice(this.handles.indexOf(handle), 1);
    }
    if (failures.length > 0)
      throw new AggregateError(failures, "native directory handles did not all close");
  }
}

/**
 * Hash exact already-read bytes without canonicalising JSON or newline spelling.
 * @param bytes - Exact finite input buffer.
 * @returns Lowercase SHA-256 content identity.
 */
export function bytesDigest(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}
