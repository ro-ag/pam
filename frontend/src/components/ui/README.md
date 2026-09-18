# PAM widgets

React + TypeScript widgets share Tailwind v4 semantic tokens in `styles/tokens.css` and palette values in `styles/themes.css`. Motion is configured once in `App.tsx` to respect reduced motion. TanStack Router owns navigation; TanStack Query owns daemon data and mutations.

Use these widgets in screens instead of rebuilding their behavior:

| Widget                             | Responsibility                                                       |
| ---------------------------------- | -------------------------------------------------------------------- |
| Button / ConfirmButton             | Action variants, enabled/disabled behavior, two-step confirmation    |
| TextField / TextArea / SelectField | Native form semantics, typed props and refs, shared field appearance |
| ActionMenu / MenuItem              | Popup placement outside scroll containers, dismissal, keyboard focus |
| PageTabs / PagePane                | Accessible page tabs and preservation of visited panes               |
| PreferenceControls                 | Appearance toggles and sliders                                       |
| Panel / Section / PageHeader       | Surfaces and page hierarchy                                          |
| Badge / FailureNote                | Status and diagnostic presentation                                   |

`Fields` default to the shared field recipe. `appearance="plain"` is reserved for controls whose surrounding widget owns its surface, or existing specialized editors. Class overrides pass through `cn` so explicit sizing wins. Keep native checkbox/radio/range semantics; they are not text fields.

Labels are nonselectable by default. Inputs remain selectable; mark copyable result text with `select-text`. Use semantic colors, existing spacing tokens and the shared focus styles. Keep permissions and requests in the screen/data layer: widgets must not call the daemon. Add behavioral regression coverage when changing focus, dismissal or form semantics; inspect rendered states for visual changes.
