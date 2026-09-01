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
      reactHooks.configs["recommended-latest"],
    ],
    languageOptions: {
      globals: globals.browser,
    },
    rules: {
      "no-restricted-syntax": ["error", ...noArbitraryTailwind],
    },
  },
);
