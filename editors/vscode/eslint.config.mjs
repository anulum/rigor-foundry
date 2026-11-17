// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — typed editor and script linting

/**
 * Apply strict typed lint and native documentation rules to every maintained editor owner.
 * Require module overviews and declaration contracts across runtime, test, script, and tool configuration files.
 * @module
 */

import js from "@eslint/js";
import { defineConfig, globalIgnores } from "eslint/config";
import jsdoc from "eslint-plugin-jsdoc";
import tseslint from "typescript-eslint";

/**
 * Apply strict typed rules and documentation requirements to every maintained native owner.
 * @satisfies {Parameters<typeof defineConfig>[0]}
 */
const shared = {
  files: ["src/**/*.ts", "test/**/*.ts", "test/**/*.mjs", "scripts/**/*.mjs", "*.mjs"],
  extends: [
    js.configs.recommended,
    tseslint.configs.strictTypeChecked,
    tseslint.configs.stylisticTypeChecked,
  ],
  languageOptions: {
    parserOptions: {
      projectService: {
        defaultProject: "tsconfig.tools.json",
        allowDefaultProject: ["eslint.config.mjs", "prettier.config.mjs"],
      },
      tsconfigRootDir: import.meta.dirname,
    },
    globals: {
      Buffer: "readonly",
      TextDecoder: "readonly",
      URL: "readonly",
      clearTimeout: "readonly",
      process: "readonly",
      setTimeout: "readonly",
    },
  },
  rules: {
    "@typescript-eslint/consistent-type-imports": "error",
    "@typescript-eslint/switch-exhaustiveness-check": "error",
    "jsdoc/require-description": "error",
    "jsdoc/require-file-overview": [
      "error",
      {
        tags: { module: { mustExist: true, preventDuplicates: true, initialCommentsOnly: true } },
      },
    ],
    "jsdoc/require-jsdoc": [
      "error",
      {
        require: {
          ClassDeclaration: true,
          FunctionDeclaration: true,
          MethodDefinition: true,
        },
      },
    ],
  },
};

export default defineConfig(
  globalIgnores(["out/**"]),
  shared,
  {
    files: ["src/**/*.ts", "test/**/*.ts"],
    extends: [jsdoc.configs["flat/recommended-typescript-error"]],
    rules: { "@typescript-eslint/explicit-function-return-type": "error" },
  },
  {
    files: ["scripts/**/*.mjs", "test/**/*.mjs", "*.mjs"],
    extends: [jsdoc.configs["flat/recommended-error"]],
  },
);
