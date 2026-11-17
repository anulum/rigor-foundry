// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — native editor source formatting

/**
 * Define the shared native source layout used by the editor development commands.
 * Keep formatting deterministic for maintained code and configuration while dependency locks remain generator-owned.
 * @module
 */

/** @satisfies {import("prettier").Config} */
export default {
  printWidth: 99,
  tabWidth: 2,
  trailingComma: "all",
};
