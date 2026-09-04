import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { initTheme } from "./lib/theme";
import { initWorkspace } from "./lib/workspace";
import "./styles.css";

// Theme before render: no frame ever paints unthemed.
initTheme();
initWorkspace();

const root = document.getElementById("root");
if (!root) {
  throw new Error("index.html is missing the #root element");
}
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
