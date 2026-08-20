import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { createFixtureBridge, createTauriBridge } from "./bridge";
import "./styles.css";

const explicitFixtureMode = import.meta.env.DEV && import.meta.env.MODE === "fixture";
const bridge = explicitFixtureMode ? createFixtureBridge() : createTauriBridge();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App bridge={bridge} />
  </StrictMode>,
);
