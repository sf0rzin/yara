import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

/*
 * There was a lint script in the pipeline's imagination and nowhere else: a
 * `react-hooks/exhaustive-deps` suppression had been sitting in ApprovalDialog
 * for the life of the file without the rule ever having run. A disable comment
 * for a rule nobody enforces is worse than no comment, because it reads as a
 * considered exception.
 */
export default tseslint.config(
  { ignores: ["dist/**", "src-tauri/**"] },

  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: globals.browser,
    },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // The hooks rules are the point of running this at all: a stale closure
      // in a screen that locks a vault is a correctness bug, not a style note.
      "react-hooks/exhaustive-deps": "error",
      // Unused values are already an error from `tsc --noEmit`, and reporting
      // them twice with two different messages helps nobody.
      "@typescript-eslint/no-unused-vars": "off",
    },
  },

  // The build and test configuration runs in Node, not the browser.
  {
    files: ["*.config.ts", "*.config.js"],
    languageOptions: { globals: globals.node },
  },
);
