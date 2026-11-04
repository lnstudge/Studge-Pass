import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**"] },
  {
    files: ["src/**/*.ts", "vite.config.ts"],
    extends: [...tseslint.configs.recommended],
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-restricted-syntax": [
        "error",
        {
          selector:
            "AssignmentExpression > MemberExpression.left[property.name='innerHTML']",
          message: "innerHTML is forbidden; use textContent.",
        },
        {
          selector:
            "AssignmentExpression > MemberExpression.left[property.name='outerHTML']",
          message: "outerHTML is forbidden; build nodes with DOM APIs.",
        },
        {
          selector: "CallExpression[callee.property.name='insertAdjacentHTML']",
          message: "insertAdjacentHTML is forbidden; build nodes with DOM APIs.",
        },
        {
          selector:
            "CallExpression[callee.object.name='document'][callee.property.name='write']",
          message: "document.write is forbidden.",
        },
      ],
    },
  }
);
