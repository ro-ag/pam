import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { createFixtureBridge, createTauriBridge } from "./bridge";
import type { ViewId } from "./domain";
import { fixtureScenario } from "./fixtures";
import "./styles.css";

const explicitFixtureMode = import.meta.env.DEV && import.meta.env.MODE === "fixture";
const query = explicitFixtureMode ? new URLSearchParams(window.location.search) : null;
const bridge = explicitFixtureMode ? createFixtureBridge(fixtureScenario(query?.get("scenario"))) : createTauriBridge();
const requestedView = query?.get("view");
const initialView: ViewId = requestedView === "flows" || requestedView === "access" ? requestedView : "current";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App bridge={bridge} initialView={initialView} />
  </StrictMode>,
);
