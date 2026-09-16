import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

// Tailwind arbitrary values — `w-[347px]`, `bg-[#0af]`, `[mask:…]` — are the
// escape hatch that erodes the token system. Any bracket segment inside a
// class string is banned; if a value is missing, it becomes a token in
// src/styles/tokens.css, never an inline literal. Matched wherever classes
// are written: className attributes and cn()/cva() arguments.
const arbitraryValue = "/\\[[^\\]\\s]+\\]/";
const noArbitraryTailwind = [
  `JSXAttribute[name.name='className'] Literal[value=${arbitraryValue}]`,
  `JSXAttribute[name.name='className'] TemplateElement[value.raw=${arbitraryValue}]`,
  `CallExpression[callee.name=/^(cn|cva)$/] Literal[value=${arbitraryValue}]`,
  `CallExpression[callee.name=/^(cn|cva)$/] TemplateElement[value.raw=${arbitraryValue}]`,
].map((selector) => ({
  selector,
  message:
    "Tailwind arbitrary values are banned: add a semantic token in src/styles/tokens.css and use its utility instead.",
}));

export default tseslint.config(
  { ignores: ["dist"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [
      js.configs.recommended,
      ...tseslint.configs.recommended,
      // Preserve the existing hooks checks; the v7 preset also opts into
      // React Compiler rules, which this app does not use.
      {
        plugins: { "react-hooks": reactHooks },
        rules: {
          "react-hooks/rules-of-hooks": "error",
          "react-hooks/exhaustive-deps": "warn",
        },
      },
    ],
    languageOptions: {
      globals: globals.browser,
    },
    rules: {
      "no-restricted-syntax": ["error", ...noArbitraryTailwind],
    },
  },
);
