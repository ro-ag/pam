import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Vitest runs without injected globals, so testing-library's automatic
// cleanup never registers itself — do it explicitly between tests.
afterEach(() => {
  cleanup();
});

// jsdom leaves window.scrollTo unimplemented and logs an error each time the
// router's scroll restoration calls it after navigation — stub it quiet.
if (typeof window !== "undefined") {
  window.scrollTo = () => {};
  Element.prototype.scrollIntoView = () => {};
}

// This jsdom build ships no window.localStorage (Node's own experimental
// localStorage shadows it); theme persistence tests need a real-enough one.
if (typeof window !== "undefined" && !window.localStorage) {
  const store = new Map<string, string>();
  const stub: Storage = {
    get length() {
      return store.size;
    },
    clear: () => store.clear(),
    getItem: (key) => store.get(key) ?? null,
    key: (index) => [...store.keys()][index] ?? null,
    removeItem: (key) => {
      store.delete(key);
    },
    setItem: (key, value) => {
      store.set(key, String(value));
    },
  };
  Object.defineProperty(window, "localStorage", {
    value: stub,
    configurable: true,
  });
}

// @xyflow/react measures nodes with ResizeObserver and reads the viewport
// transform through DOMMatrixReadOnly on mount; jsdom ships neither.
if (typeof window !== "undefined") {
  if (!("ResizeObserver" in window)) {
    class ResizeObserverStub {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
    Object.defineProperty(window, "ResizeObserver", {
      value: ResizeObserverStub,
      configurable: true,
    });
  }
  if (!("DOMMatrixReadOnly" in window)) {
    class DOMMatrixReadOnlyStub {
      m22 = 1;
    }
    Object.defineProperty(window, "DOMMatrixReadOnly", {
      value: DOMMatrixReadOnlyStub,
      configurable: true,
    });
  }
}
