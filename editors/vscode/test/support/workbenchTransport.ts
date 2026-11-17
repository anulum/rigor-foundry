// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — real owned workbench transport

/**
 * Connect to the actual owned renderer without depending on the extension-host API.
 * Preserve bounded requests, original responses and immediate transport-closure refusal.
 * @module
 */

import assert from "node:assert/strict";
import { appendFile, readFile } from "node:fs/promises";
import path from "node:path";
import {
  dispatchWorkbenchReply,
  requireWorkbenchAddress,
  workbenchAddress,
  workbenchPort,
  workbenchResult,
} from "./workbenchProtocol.js";

/** A connection to the actual renderer of an independently owned workbench. */
export interface NativeUiConnection {
  /** Exact validated renderer URL, retained for explicit same-profile reconnection. */
  readonly address: string;
  /** Port read independently from that owned profile. */
  readonly port: number;
  /** Send one documented browser command and retain its actual response. */
  readonly send: (method: string, params?: Record<string, unknown>) => Promise<unknown>;
  /** Disconnect this transport without closing the application. */
  readonly close: () => void;
}

/**
 * Attach to a previously observed endpoint of the same owned profile.
 * @param endpoint - Real renderer address, including a stale address after owned-app closure.
 * @param port - Independently observed port from that profile.
 * @param journal - Owned file receiving original request/response envelopes.
 * @returns Open bounded connection, or an authored connection refusal.
 */
export async function connectWorkbench(
  endpoint: string,
  port: number,
  journal: string,
): Promise<NativeUiConnection> {
  const address = new URL(endpoint);
  requireWorkbenchAddress(address, port);
  const socket = new WebSocket(address);
  const handshake = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await new Promise<void>((resolve, reject) => {
      timer = setTimeout(
        reject,
        10_000,
        new Error("owned workbench connection exceeded its deadline"),
      );
      socket.addEventListener(
        "open",
        () => {
          resolve();
        },
        { once: true, signal: handshake.signal },
      );
      socket.addEventListener(
        "error",
        () => {
          reject(new Error("owned workbench connection failed"));
        },
        { once: true, signal: handshake.signal },
      );
    });
  } catch (error: unknown) {
    socket.close();
    throw error;
  } finally {
    clearTimeout(timer);
    handshake.abort();
  }

  let sequence = 0;
  return {
    address: address.href,
    port,
    send: async (method, params = {}): Promise<unknown> => {
      sequence += 1;
      const id = sequence;
      const request = { id, method, params };
      const envelope = await new Promise<unknown>((resolve, reject) => {
        const finish = (error: Error | undefined, value: unknown): void => {
          clearTimeout(commandTimer);
          socket.removeEventListener("message", onMessage);
          socket.removeEventListener("close", onClose);
          if (error === undefined) resolve(value);
          else reject(error);
        };
        const onClose = (): void => {
          finish(new Error("owned workbench connection closed during input"), undefined);
        };
        const onMessage = (event: MessageEvent): void => {
          dispatchWorkbenchReply(event.data, id, finish);
        };
        const commandTimer = setTimeout(() => {
          finish(new Error("owned workbench command exceeded its deadline"), undefined);
        }, 10_000);
        socket.addEventListener("message", onMessage);
        socket.addEventListener("close", onClose, { once: true });
        socket.send(JSON.stringify(request));
      });
      await appendFile(journal, JSON.stringify({ request, response: envelope }) + "\n", "utf8");
      return workbenchResult(envelope, method);
    },
    close: (): void => {
      socket.close();
    },
  };
}

/**
 * Discover and connect only to the renderer published by the owned application profile.
 * @param fixture - Actual workspace inside that profile's launch sandbox.
 * @returns A connection to the real workbench, with no replacement browser or API object.
 */
export async function connectNativeUi(fixture: string): Promise<NativeUiConnection> {
  const profile = path.join(path.dirname(fixture), "user-data");
  const port = workbenchPort(await readFile(path.join(profile, "DevToolsActivePort"), "utf8"));
  const response = await fetch(`http://127.0.0.1:${String(port)}/json/list`, {
    signal: AbortSignal.timeout(10_000),
  });
  assert.equal(response.ok, true);
  const targets: unknown = await response.json();
  const address = workbenchAddress(targets, port);
  return await connectWorkbench(
    address.href,
    port,
    path.join(fixture, ".rigor", "native-ui-protocol.ndjson"),
  );
}
