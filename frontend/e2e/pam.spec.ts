import { expect, type Page, test } from "@playwright/test";

type ViewName = "current" | "flows" | "access";

const responsiveWidths = [1_180, 960, 780, 600, 320] as const;
const runtimeErrors = new WeakMap<Page, string[]>();

test.beforeEach(async ({ page }) => {
  const errors: string[] = [];
  runtimeErrors.set(page, errors);
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("pageerror", (error) => errors.push(error.message));
});

test.afterEach(async ({ page }) => {
  expect(runtimeErrors.get(page) ?? []).toEqual([]);
});

async function openFixture(
  page: Page,
  scenario = "solved",
  view: ViewName = "current",
): Promise<void> {
  await page.goto(`/?scenario=${scenario}&view=${view}`);
  await page.locator(".app-shell").waitFor();
  await page.evaluate(async () => {
    await document.fonts.ready;
    await Promise.all(
      Array.from(document.images, (image) => (
        image.complete
          ? Promise.resolve()
          : new Promise<void>((resolve) => {
              image.addEventListener("load", () => resolve(), { once: true });
              image.addEventListener("error", () => resolve(), { once: true });
            })
      )),
    );
  });
}

async function horizontalMetrics(page: Page) {
  return page.evaluate(() => ({
    viewport: window.innerWidth,
    htmlClient: document.documentElement.clientWidth,
    htmlScroll: document.documentElement.scrollWidth,
    bodyClient: document.body.clientWidth,
    bodyScroll: document.body.scrollWidth,
    shellClient: document.querySelector<HTMLElement>(".app-shell")?.clientWidth ?? -1,
    shellScroll: document.querySelector<HTMLElement>(".app-shell")?.scrollWidth ?? -1,
  }));
}

test.describe("responsive visual contract", () => {
  for (const width of responsiveWidths) {
    test(`keeps the solved Current surface bounded at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 800 });
      await openFixture(page);
      await expect(page.getByRole("heading", { name: "payments-api" })).toBeVisible();

      const geometry = await page.evaluate(() => {
        const rect = (selector: string) => {
          const box = document.querySelector<HTMLElement>(selector)?.getBoundingClientRect();
          return box ? { x: box.x, y: box.y, width: box.width, height: box.height, right: box.right } : null;
        };
        const separator = document.querySelector<HTMLElement>(".resize-separator");
        return {
          shell: rect(".app-shell"),
          sidebar: rect(".sidebar"),
          separator: rect(".resize-separator"),
          separatorDisplay: separator ? getComputedStyle(separator).display : "missing",
          workspace: rect(".workspace"),
          toolbar: rect(".toolbar"),
        };
      });
      const horizontal = await horizontalMetrics(page);

      expect(horizontal.htmlScroll).toBe(horizontal.htmlClient);
      expect(horizontal.bodyScroll).toBe(horizontal.bodyClient);
      expect(horizontal.shellScroll).toBe(horizontal.shellClient);
      expect(geometry.shell?.width).toBe(width);

      if (width > 780) {
        expect(geometry.sidebar?.width).toBe(248);
        expect(geometry.separator?.width).toBe(5);
        expect(geometry.workspace?.x).toBe(253);
        expect(geometry.workspace?.y).toBe(8);
        expect(geometry.workspace?.right).toBe(width - 8);
        expect(geometry.toolbar?.height).toBe(44);
      } else if (width > 600) {
        expect(geometry.sidebar?.width).toBe(68);
        expect(geometry.separator?.width).toBe(5);
        expect(geometry.workspace?.x).toBe(73);
        expect(geometry.workspace?.y).toBe(8);
        expect(geometry.workspace?.right).toBe(width - 8);
        expect(geometry.toolbar?.height).toBe(44);
      } else {
        expect(geometry.sidebar?.height).toBe(68);
        expect(geometry.separatorDisplay).toBe("none");
        expect(geometry.workspace?.x).toBe(4);
        expect(geometry.workspace?.y).toBe(72);
        expect(geometry.workspace?.right).toBe(width - 4);
        expect(geometry.toolbar?.height).toBeGreaterThanOrEqual(44);
      }

      await expect(page).toHaveScreenshot(`current-solved-${width}x800.png`);
    });
  }

  test("keeps every primary handoff action reachable at effective 320px", async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 800 });
    await openFixture(page);
    const actions = ["Copy outcome brief", "Open evidence", "Continue flow"];

    for (const name of actions) {
      const action = page.getByRole("button", { name, exact: true });
      await action.scrollIntoViewIfNeeded();
      await expect(action).toBeVisible();
      const box = await action.boundingBox();
      expect(box).not.toBeNull();
      expect(box!.x).toBeGreaterThanOrEqual(0);
      expect(box!.x + box!.width).toBeLessThanOrEqual(320);
    }

    const horizontal = await horizontalMetrics(page);
    expect(horizontal.htmlScroll).toBe(horizontal.htmlClient);
    expect(horizontal.bodyScroll).toBe(horizontal.bodyClient);
    await expect(page).toHaveScreenshot("current-actions-320x800.png");
  });
});

test.describe("production-shaped interactions", () => {
  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1_180, height: 800 });
  });

  test("uses the complete keyboard project-menu contract", async ({ page }) => {
    await openFixture(page);
    const trigger = page.getByRole("button", { name: "payments-api" });
    await trigger.focus();
    await page.keyboard.press("ArrowDown");
    const menu = page.getByRole("menu");
    await expect(menu).toBeVisible();
    await expect(page.getByRole("menuitemradio", { name: /payments-api/ })).toBeFocused();
    await expect(page).toHaveScreenshot("project-menu-1180x800.png");

    await page.keyboard.press("End");
    await expect(page.getByRole("menuitemradio", { name: /^docs/ })).toBeFocused();
    await page.keyboard.press("Home");
    await expect(page.getByRole("menuitemradio", { name: /payments-api/ })).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(menu).toBeHidden();
    await expect(trigger).toBeFocused();
  });

  test("navigates the command palette and replaces it with one queue drawer", async ({ page }) => {
    await openFixture(page);
    const opener = page.getByRole("button", { name: "Open command palette (⌘K)" });
    await opener.focus();
    await page.keyboard.press("Control+k");
    const palette = page.getByRole("dialog", { name: "Command palette" });
    await expect(palette).toBeVisible();
    await expect(page.getByRole("searchbox", { name: "Search commands" })).toBeFocused();
    await expect(page).toHaveScreenshot("command-palette-1180x800.png");

    await page.getByRole("searchbox", { name: "Search commands" }).fill("queue");
    await page.keyboard.press("ArrowDown");
    await expect(page.getByRole("option", { name: /Open project queue/ })).toBeFocused();
    await page.keyboard.press("Enter");
    const queue = page.getByRole("dialog", { name: "Project queue" });
    await expect(queue).toBeVisible();
    await expect(page.getByRole("dialog")).toHaveCount(1);
    await expect(page).toHaveScreenshot("queue-drawer-1180x800.png");

    await page.keyboard.press("Escape");
    await expect(queue).toBeHidden();
    await expect(opener).toBeFocused();
  });

  test("opens bounded evidence and restores the exact opener", async ({ page }) => {
    await openFixture(page, "evidence-available");
    const opener = page.getByRole("button", { name: "Open Evidence 1" });
    await expect(opener).toHaveAttribute("aria-description", "44444444-4444-4444-8444-444444444444");
    await opener.click();
    const drawer = page.getByRole("dialog", { name: "Evidence" });
    await expect(drawer).toBeVisible();
    await expect(drawer.getByText("44444444-4444-4444-8444-444444444444")).toBeVisible();
    await expect(page).toHaveScreenshot("evidence-drawer-1180x800.png");
    await page.keyboard.press("Escape");
    await expect(drawer).toBeHidden();
    await expect(opener).toBeFocused();
  });

  test("stacks Flows at 960px and provides keyboard tabs", async ({ page }) => {
    await page.setViewportSize({ width: 960, height: 800 });
    await openFixture(page, "solved", "flows");
    await page.getByRole("button", { name: /after-merge-checks/ }).click();
    const source = page.getByRole("textbox", { name: "Flow TOML source" });
    const original = await source.inputValue();
    await source.fill(original.replace("revision = 4", "revision = 5"));
    await page.getByRole("button", { name: "Validate" }).click();
    const dryRun = page.getByRole("tab", { name: "Dry run" });
    await expect(dryRun).toBeVisible();
    await dryRun.focus();
    await page.keyboard.press("End");
    await expect(page.getByRole("tab", { name: /Version diff · changed/ })).toBeFocused();
    const columns = await page.locator(".flow-workspace").evaluate((element) => getComputedStyle(element).gridTemplateColumns);
    expect(columns.trim().split(/\s+/)).toHaveLength(1);
    const horizontal = await horizontalMetrics(page);
    expect(horizontal.bodyScroll).toBe(horizontal.bodyClient);
    await expect(page).toHaveScreenshot("flows-validated-960x800.png");
  });

  test("executes the bounded recovery action at effective 320px", async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 800 });
    await openFixture(page, "missing-credential");
    await expect(page.getByRole("heading", { name: "Authenticated project state is unavailable" })).toBeVisible();
    await page.getByRole("button", { name: "Register GUI caller" }).click();
    await expect(page.getByRole("heading", { name: "Ready for the next agent" })).toBeVisible();
    const horizontal = await horizontalMetrics(page);
    expect(horizontal.bodyScroll).toBe(horizontal.bodyClient);
  });

  test("honors explicit reduced motion and forced-color focus", async ({ page }) => {
    await openFixture(page);
    const root = page.locator("html");
    const animationDurationMs = () => page.locator("body").evaluate(() => {
      const value = getComputedStyle(document.body).animationDuration;
      return value.endsWith("ms") ? Number.parseFloat(value) : Number.parseFloat(value) * 1_000;
    });

    await root.evaluate((element) => element.setAttribute("data-reduced-motion", "always"));
    expect(await animationDurationMs()).toBeCloseTo(0.01, 5);

    await root.evaluate((element) => element.removeAttribute("data-reduced-motion"));
    await page.emulateMedia({ reducedMotion: "reduce" });
    expect(await animationDurationMs()).toBeCloseTo(0.01, 5);

    await root.evaluate((element) => element.setAttribute("data-reduced-motion", "never"));
    expect(await animationDurationMs()).toBe(0);

    await page.emulateMedia({ forcedColors: "active", reducedMotion: "reduce" });
    expect(await page.evaluate(() => matchMedia("(forced-colors: active)").matches)).toBe(true);
    const refresh = page.getByRole("button", { name: "Refresh project" });
    await refresh.focus();
    const focus = await refresh.evaluate((element) => {
      const style = getComputedStyle(element);
      return { outlineStyle: style.outlineStyle, outlineWidth: style.outlineWidth };
    });
    expect(focus.outlineStyle).toBe("solid");
    expect(Number.parseFloat(focus.outlineWidth)).toBeGreaterThanOrEqual(2);
  });
});
