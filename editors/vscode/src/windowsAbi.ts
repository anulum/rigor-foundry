// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — typed native Windows ABI

/**
 * Bind Windows x64 resource APIs with their actual native layouts and calling convention.
 * Load this module only on Windows; callers retain every buffer and handle until completion.
 * @module
 */

import { assertWindowsNativeImage } from "./windowsNativeAsset.js";
import * as koffi from "#koffi-runtime";
import type { KoffiFunc } from "koffi";

assertWindowsNativeImage();

/** Native pointer, kept as an exact integer rather than a JavaScript floating-point address. */
export type NativePointer = bigint | null;

/** Native IO_STATUS_BLOCK output, whose union is pointer-sized on the supported ABI. */
export interface NativeIoStatus {
  /** Native status union; callers use the NtCreateFile return status. */
  status: unknown;
  /** Native byte/disposition count. */
  information: unknown;
}

/** Native object-manager lookup with a retained parent and separately retained UTF-16 name. */
export interface NativeObjectAttributes {
  /** Exact native structure size. */
  length: number;
  /** Actual retained parent directory handle. */
  root: bigint;
  /** Counted UTF-16 component, with a separately marshalled buffer. */
  name: {
    /** UTF-16 name length in bytes, without the trailing NUL. */
    length: number;
    /** Retained UTF-16 buffer capacity in bytes. */
    maximumLength: number;
    /** Exact component retained through the native lookup. */
    buffer: string;
  };
  /** Case-insensitive, no-reparse lookup flags. */
  attributes: number;
  /** Borrowed self-relative security descriptor at creation. */
  security: NativePointer;
  /** No impersonation quality-of-service override. */
  quality: null;
}

/** Actual Win32 process handles and IDs populated by CreateProcessW. */
export interface NativeProcessInfo {
  /** Owned process handle, validated before use. */
  process: unknown;
  /** Owned primary thread handle, validated before use. */
  thread: unknown;
  /** Actual process identifier. */
  pid: number;
  /** Actual primary thread identifier. */
  tid: number;
}

/**
 * Decode a native output pointer without permitting lossy address conversion.
 * @param value - Unknown output from the FFI boundary.
 * @returns Exact pointer, including NULL where the caller permits it.
 * @throws {Error} If the ABI returned an unexpected representation.
 */
export function nativePointer(value: unknown): NativePointer {
  if (value === null || typeof value === "bigint") return value;
  throw new Error("native Windows pointer has an unsupported representation");
}

/** FILETIME uses two DWORDs and four-byte alignment, including inside file information. */
const fileTime = koffi.struct("RfFileTime", { low: "uint32_t", high: "uint32_t" });

/** Win32 fixed layouts, computed by Koffi using the platform C ABI. */
export const nativeTypes = {
  /** Actual BY_HANDLE_FILE_INFORMATION output for one retained file handle. */
  fileInformation: koffi.struct("RfFileInformation", {
    attributes: "uint32_t",
    created: fileTime,
    accessed: fileTime,
    written: fileTime,
    volume: "uint32_t",
    sizeHigh: "uint32_t",
    sizeLow: "uint32_t",
    links: "uint32_t",
    indexHigh: "uint32_t",
    indexLow: "uint32_t",
  }),
  /** Counted UTF-16 component used for object-manager relative lookup. */
  unicodeString: koffi.struct("RfUnicodeString", {
    length: "uint16_t",
    maximumLength: "uint16_t",
    buffer: "char16_t *",
  }),
  /** Native completion status and pointer-sized information count. */
  ioStatus: koffi.struct("RfIoStatus", { status: "void *", information: "uintptr_t" }),
  /** Descriptor and inheritance fields for a newly created native resource. */
  securityAttributes: koffi.struct("RfSecurityAttributes", {
    length: "uint32_t",
    descriptor: "void *",
    inherit: "int32_t",
  }),
  /** Created process and primary thread handles with their actual identifiers. */
  processInfo: koffi.struct("RfProcessInfo", {
    process: "void *",
    thread: "void *",
    pid: "uint32_t",
    tid: "uint32_t",
  }),
  /** Process startup layout including the explicit standard-stream handles. */
  startupInfo: koffi.struct("RfStartupInfo", {
    cb: "uint32_t",
    reserved: "void *",
    desktop: "void *",
    title: "void *",
    x: "uint32_t",
    y: "uint32_t",
    xSize: "uint32_t",
    ySize: "uint32_t",
    xChars: "uint32_t",
    yChars: "uint32_t",
    fill: "uint32_t",
    flags: "uint32_t",
    show: "uint16_t",
    reservedBytes: "uint16_t",
    reservedData: "void *",
    stdin: "void *",
    stdout: "void *",
    stderr: "void *",
  }),
  /** Job resource limits and scheduling fields in native ABI order. */
  basicLimits: koffi.struct("RfBasicLimits", {
    processTime: "int64_t",
    jobTime: "int64_t",
    flags: "uint32_t",
    minimumWorkingSet: "uintptr_t",
    maximumWorkingSet: "uintptr_t",
    activeProcesses: "uint32_t",
    affinity: "uintptr_t",
    priority: "uint32_t",
    scheduling: "uint32_t",
  }),
  /** Actual job counters, including the active process membership count. */
  jobAccounting: koffi.struct("RfJobAccounting", {
    totalUser: "int64_t",
    totalKernel: "int64_t",
    periodUser: "int64_t",
    periodKernel: "int64_t",
    pageFaults: "uint32_t",
    totalProcesses: "uint32_t",
    activeProcesses: "uint32_t",
    terminatedProcesses: "uint32_t",
  }),
};

/** Native object attributes, including native alignment of its pointer fields. */
export const objectAttributesType = koffi.struct("RfObjectAttributes", {
  length: "uint32_t",
  root: "void *",
  name: "RfUnicodeString *",
  attributes: "uint32_t",
  security: "void *",
  quality: "void *",
});
/** Extended startup info for an explicit inherited-handle list. */
export const startupInfoExType = koffi.struct("RfStartupInfoEx", {
  startup: nativeTypes.startupInfo,
  attributes: "void *",
});
/** Complete extended job limit layout, including IO_COUNTERS and memory limits. */
export const extendedLimitsType = koffi.struct("RfExtendedLimits", {
  basic: nativeTypes.basicLimits,
  ioCounters: koffi.array("uint64_t", 6),
  processMemory: "uintptr_t",
  jobMemory: "uintptr_t",
  peakProcessMemory: "uintptr_t",
  peakJobMemory: "uintptr_t",
});

/** Explicit Windows system library; no caller-supplied DLL path. */
const kernel = koffi.load("kernel32.dll");
/** Native object-manager library for parent-relative file operations. */
const nt = koffi.load("ntdll.dll");
/** Token and protected security-descriptor operations. */
const advapi = koffi.load("advapi32.dll");

/** Last-error read used immediately after synchronous failed native calls. */
export const getLastError: KoffiFunc<() => number> = kernel.func(
  "uint32_t __stdcall GetLastError()",
);
/** Close one actual owned native handle. */
export const closeHandle: KoffiFunc<(handle: bigint) => number> = kernel.func(
  "int32_t __stdcall CloseHandle(void *handle)",
);
/** Borrow the current process pseudo handle without assuming an integer width. */
export const getCurrentProcess: KoffiFunc<() => unknown> = kernel.func(
  "void * __stdcall GetCurrentProcess()",
);
/** Duplicate a noninheritable owned directory reference with the same access rights. */
export const duplicateHandle: KoffiFunc<
  (
    sourceProcess: bigint,
    source: bigint,
    targetProcess: bigint,
    target: unknown[],
    access: number,
    inherit: number,
    options: number,
  ) => number
> = kernel.func(
  "int32_t __stdcall DuplicateHandle(void *sourceProcess, void *source, void *targetProcess, _Out_ void **target, uint32_t access, int32_t inherit, uint32_t options)",
);
/** Open the explicit local volume root without following a reparse point. */
export const createFile: KoffiFunc<
  (
    path: string,
    access: number,
    share: number,
    security: null,
    disposition: number,
    flags: number,
    template: null,
  ) => unknown
> = kernel.func(
  "void * __stdcall CreateFileW(const char16_t *path, uint32_t access, uint32_t share, void *security, uint32_t disposition, uint32_t flags, void *template)",
);
/** Open or create one child using the retained native parent object. */
export const ntCreateFile: KoffiFunc<
  (
    handle: unknown[],
    access: number,
    attributes: NativeObjectAttributes,
    status: NativeIoStatus,
    allocation: null,
    flags: number,
    share: number,
    disposition: number,
    options: number,
    ea: null,
    eaLength: number,
  ) => number
> = nt.func(
  "int32_t __stdcall NtCreateFile(_Out_ void **handle, uint32_t access, RfObjectAttributes *attributes, _Out_ RfIoStatus *status, void *allocation, uint32_t flags, uint32_t share, uint32_t disposition, uint32_t options, void *ea, uint32_t eaLength)",
);
/** Translate a native NTSTATUS without depending on a later last-error value. */
export const ntStatusToDosError: KoffiFunc<(status: number) => number> = nt.func(
  "uint32_t __stdcall RtlNtStatusToDosError(int32_t status)",
);
/** Read handle-bound file metadata into its exact native structure. */
export const getFileInformation: KoffiFunc<(handle: bigint, result: Buffer) => number> =
  kernel.func("int32_t __stdcall GetFileInformationByHandle(void *handle, _Out_ void *result)");
/** Require an actual disk file or directory handle. */
export const getFileType: KoffiFunc<(handle: bigint) => number> = kernel.func(
  "uint32_t __stdcall GetFileType(void *handle)",
);
/** Resolve the retained native object to a complete GUID or NT-device name. */
export const getFinalPath: KoffiFunc<
  (handle: bigint, buffer: Buffer, capacity: number, flags: number) => number
> = kernel.func(
  "uint32_t __stdcall GetFinalPathNameByHandleW(void *handle, _Out_ void *buffer, uint32_t capacity, uint32_t flags)",
);
/** Check that the explicit drive is fixed local storage. */
export const getDriveType: KoffiFunc<(root: string) => number> = kernel.func(
  "uint32_t __stdcall GetDriveTypeW(const char16_t *root)",
);
/** Inspect the filesystem through an already retained directory. */
export const getVolumeInformation: KoffiFunc<
  (
    handle: bigint,
    volume: null,
    volumeSize: number,
    serial: null,
    maximum: null,
    flags: null,
    filesystem: Buffer,
    capacity: number,
  ) => number
> = kernel.func(
  "int32_t __stdcall GetVolumeInformationByHandleW(void *handle, void *volume, uint32_t volumeSize, void *serial, void *maximum, void *flags, _Out_ void *filesystem, uint32_t capacity)",
);
/** Read bounded bytes from the exact retained file or a pipe known to contain data. */
export const readFile: KoffiFunc<
  (handle: bigint, buffer: Buffer, length: number, count: number[], overlapped: null) => number
> = kernel.func(
  "int32_t __stdcall ReadFile(void *handle, _Out_ void *buffer, uint32_t length, _Out_ uint32_t *count, void *overlapped)",
);
/** Write exact bytes; the async form keeps large writes outside the extension event loop. */
export const writeFile: KoffiFunc<
  (handle: bigint, buffer: Buffer, length: number, count: number[], overlapped: null) => number
> = kernel.func(
  "int32_t __stdcall WriteFile(void *handle, const void *buffer, uint32_t length, _Out_ uint32_t *count, void *overlapped)",
);
/** Flush actual NTFS file data before exposing a created input. */
export const flushFile: KoffiFunc<(handle: bigint) => number> = kernel.func(
  "int32_t __stdcall FlushFileBuffers(void *handle)",
);
/** Mark only an owned file handle for deletion. */
export const setFileInformation: KoffiFunc<
  (handle: bigint, kind: number, information: Buffer, length: number) => number
> = kernel.func(
  "int32_t __stdcall SetFileInformationByHandle(void *handle, int32_t kind, const void *information, uint32_t length)",
);
/** Allocate one inherited anonymous pipe. */
export const createPipe: KoffiFunc<
  (reader: unknown[], writer: unknown[], security: Buffer, size: number) => number
> = kernel.func(
  "int32_t __stdcall CreatePipe(_Out_ void **reader, _Out_ void **writer, RfSecurityAttributes *security, uint32_t size)",
);
/** Remove inheritance from the parent's pipe ends. */
export const setHandleInformation: KoffiFunc<
  (handle: bigint, mask: number, flags: number) => number
> = kernel.func(
  "int32_t __stdcall SetHandleInformation(void *handle, uint32_t mask, uint32_t flags)",
);
/** Observe available pipe bytes without blocking the extension event loop. */
export const peekPipe: KoffiFunc<
  (
    handle: bigint,
    buffer: null,
    length: number,
    read: null,
    available: number[],
    remaining: null,
  ) => number
> = kernel.func(
  "int32_t __stdcall PeekNamedPipe(void *handle, void *buffer, uint32_t length, void *read, _Out_ uint32_t *available, void *remaining)",
);
/** Create a private unnamed process job. */
export const createJob: KoffiFunc<(security: null, name: null) => unknown> = kernel.func(
  "void * __stdcall CreateJobObjectW(void *security, const char16_t *name)",
);
/** Apply job kill-on-close and committed-memory limits. */
export const setJobInformation: KoffiFunc<
  (job: bigint, kind: number, information: Buffer, size: number) => number
> = kernel.func(
  "int32_t __stdcall SetInformationJobObject(void *job, int32_t kind, const void *information, uint32_t size)",
);
/** Query confirmed job membership through the still-owned job handle. */
export const queryJobInformation: KoffiFunc<
  (job: bigint, kind: number, information: Buffer, size: number, length: null) => number
> = kernel.func(
  "int32_t __stdcall QueryInformationJobObject(void *job, int32_t kind, _Out_ void *information, uint32_t size, void *length)",
);
/** Assign the suspended process before its primary thread can run. */
export const assignJob: KoffiFunc<(job: bigint, processHandle: bigint) => number> = kernel.func(
  "int32_t __stdcall AssignProcessToJobObject(void *job, void *processHandle)",
);
/** Request termination of every member of the owned job. */
export const terminateJob: KoffiFunc<(job: bigint, code: number) => number> = kernel.func(
  "int32_t __stdcall TerminateJobObject(void *job, uint32_t code)",
);
/** Terminate the owned suspended child if job assignment never succeeded. */
export const terminateProcess: KoffiFunc<(processHandle: bigint, code: number) => number> =
  kernel.func("int32_t __stdcall TerminateProcess(void *processHandle, uint32_t code)");
/** Poll actual process termination without blocking. */
export const waitForObject: KoffiFunc<(handle: bigint, milliseconds: number) => number> =
  kernel.func("uint32_t __stdcall WaitForSingleObject(void *handle, uint32_t milliseconds)");
/** Capture the completed leader's real exit status. */
export const getExitCode: KoffiFunc<(processHandle: bigint, code: number[]) => number> =
  kernel.func("int32_t __stdcall GetExitCodeProcess(void *processHandle, _Out_ uint32_t *code)");
/** Obtain the created process's complete native image name before resuming it. */
export const queryProcessImage: KoffiFunc<
  (processHandle: bigint, flags: number, name: Buffer, capacity: number[]) => number
> = kernel.func(
  "int32_t __stdcall QueryFullProcessImageNameW(void *processHandle, uint32_t flags, _Out_ void *name, _Inout_ uint32_t *capacity)",
);
/** Resume exactly the once-suspended primary thread. */
export const resumeThread: KoffiFunc<(thread: bigint) => number> = kernel.func(
  "uint32_t __stdcall ResumeThread(void *thread)",
);
/** Allocate the process attribute list in caller-owned storage. */
export const initializeAttributes: KoffiFunc<
  (attributes: Buffer | null, count: number, flags: number, size: unknown[]) => number
> = kernel.func(
  "int32_t __stdcall InitializeProcThreadAttributeList(void *attributes, uint32_t count, uint32_t flags, _Inout_ uintptr_t *size)",
);
/** Restrict inherited handles to the three explicitly owned child pipe ends. */
export const updateAttributes: KoffiFunc<
  (
    attributes: Buffer,
    flags: number,
    kind: number,
    value: Buffer,
    size: number,
    previous: null,
    returned: null,
  ) => number
> = kernel.func(
  "int32_t __stdcall UpdateProcThreadAttribute(void *attributes, uint32_t flags, uintptr_t kind, const void *value, uintptr_t size, void *previous, void *returned)",
);
/** Release native attribute-list bookkeeping before releasing its backing buffer. */
export const deleteAttributes: KoffiFunc<(attributes: Buffer) => void> = kernel.func(
  "void __stdcall DeleteProcThreadAttributeList(void *attributes)",
);
/** Create an explicit image suspended, with Unicode argv/environment and an exact handle list. */
export const createProcess: KoffiFunc<
  (
    image: string,
    command: Buffer,
    processSecurity: null,
    threadSecurity: null,
    inherit: number,
    flags: number,
    environment: Buffer,
    cwd: string,
    startup: Buffer,
    processInfo: NativeProcessInfo,
  ) => number
> = kernel.func(
  "int32_t __stdcall CreateProcessW(const char16_t *image, void *command, void *processSecurity, void *threadSecurity, int32_t inherit, uint32_t flags, const void *environment, const char16_t *cwd, RfStartupInfoEx *startup, _Out_ RfProcessInfo *processInfo)",
);
/** Open only the current process token for identity queries. */
export const openProcessToken: KoffiFunc<
  (processHandle: bigint, access: number, token: unknown[]) => number
> = advapi.func(
  "int32_t __stdcall OpenProcessToken(void *processHandle, uint32_t access, _Out_ void **token)",
);
/** Obtain a bounded TOKEN_USER buffer. */
export const getTokenInformation: KoffiFunc<
  (
    token: bigint,
    kind: number,
    result: Buffer | null,
    capacity: number,
    length: number[],
  ) => number
> = advapi.func(
  "int32_t __stdcall GetTokenInformation(void *token, int32_t kind, _Out_ void *result, uint32_t capacity, _Out_ uint32_t *length)",
);
/** Allocate the string representation of a retained user SID. */
export const sidToString: KoffiFunc<(sid: bigint, result: unknown[]) => number> = advapi.func(
  "int32_t __stdcall ConvertSidToStringSidW(void *sid, _Out_ void **result)",
);
/** Allocate an explicit protected self-relative security descriptor. */
export const stringToSecurityDescriptor: KoffiFunc<
  (sddl: string, revision: number, result: unknown[], size: null) => number
> = advapi.func(
  "int32_t __stdcall ConvertStringSecurityDescriptorToSecurityDescriptorW(const char16_t *sddl, uint32_t revision, _Out_ void **result, void *size)",
);
/** Apply the protected DACL to the same retained object, requiring WRITE_DAC access. */
export const setObjectSecurity: KoffiFunc<
  (handle: bigint, information: number, descriptor: bigint) => number
> = advapi.func(
  "int32_t __stdcall SetKernelObjectSecurity(void *handle, uint32_t information, void *descriptor)",
);
/** Release only allocations returned by Windows LocalAlloc-based APIs. */
export const localFree: KoffiFunc<(pointer: bigint) => unknown> = kernel.func(
  "void * __stdcall LocalFree(void *pointer)",
);

export { koffi };
