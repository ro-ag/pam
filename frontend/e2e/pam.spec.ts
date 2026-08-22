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
        expect(geometry.workspace?.y).toBe(10);
        expect(geometry.workspace?.right).toBe(width - 10);
        expect(geometry.toolbar?.height).toBe(52);
      } else if (width > 600) {
        expect(geometry.sidebar?.width).toBe(68);
        expect(geometry.separator?.width).toBe(5);
        expect(geometry.workspace?.x).toBe(73);
        expect(geometry.workspace?.y).toBe(8);
        expect(geometry.workspace?.right).toBe(width - 8);
        expect(geometry.toolbar?.height).toBe(52);
      } else {
        expect(geometry.sidebar?.height).toBe(68);
        expect(geometry.separatorDisplay).toBe("none");
        expect(geometry.workspace?.x).toBe(4);
        expect(geometry.workspace?.y).toBe(72);
        expect(geometry.workspace?.right).toBe(width - 4);
        expect(geometry.toolbar?.height).toBeGreaterThanOrEqual(50);
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

  test("lets an active timeline use the full canvas when no outcome exists", async ({ page }) => {
    await page.setViewportSize({ width: 1_180, height: 800 });
    await openFixture(page, "active");
    await expect(page.locator(".outcome-card")).toHaveCount(0);

    const geometry = await page.evaluate(() => {
      const layout = document.querySelector<HTMLElement>(".timeline-layout")!.getBoundingClientRect();
      const timeline = document.querySelector<HTMLElement>(".timeline-column")!.getBoundingClientRect();
      return {
        layout: { left: layout.left, right: layout.right, width: layout.width },
        timeline: { left: timeline.left, right: timeline.right, width: timeline.width },
      };
    });
    expect(geometry.timeline).toEqual(geometry.layout);
    await expect(page).toHaveScreenshot("current-active-1180x800.png");
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

test.describe("selectable theme families and variants", () => {
  const appearances = [
    { theme: "ventisquero", mode: "light", page: "rgb(246, 243, 236)", surface: "rgb(253, 252, 249)", accent: "#1d7893", font: "Archivo", asset: "ventisquero-yelcho.png" },
    { theme: "ventisquero", mode: "dark", page: "rgb(6, 9, 13)", surface: "rgb(12, 17, 23)", accent: "#1d7893", font: "Archivo", asset: "ventisquero-yelcho.png" },
    { theme: "vina", mode: "light", page: "rgb(245, 243, 235)", surface: "rgb(253, 252, 249)", accent: "#a84595", font: "Space Grotesk", asset: "vina-sunset.png" },
    { theme: "vina", mode: "dark", page: "rgb(10, 5, 20)", surface: "rgb(26, 11, 46)", accent: "#a84595", font: "Space Grotesk", asset: "vina-sunset.png" },
  ] as const;

  for (const appearance of appearances) {
    test(`renders ${appearance.theme} ${appearance.mode} as an independent full-canvas theme`, async ({ page }) => {
      await page.addInitScript(({ theme, mode }) => {
        localStorage.setItem("pam-theme", theme);
        localStorage.setItem("pam-theme-mode", mode);
      }, appearance);
      await page.setViewportSize({ width: 1_180, height: 800 });
      await openFixture(page);

      const computed = await page.evaluate(() => {
        const workspace = document.querySelector<HTMLElement>(".workspace")!;
        const sidebar = document.querySelector<HTMLElement>(".sidebar")!;
        const separator = document.querySelector<HTMLElement>(".resize-separator")!;
        const surface = document.querySelector<HTMLElement>(".project-overview")!;
        const title = document.querySelector<HTMLElement>(".project-header h1")!;
        const art = document.querySelector<HTMLElement>(".project-header-art")!;
        const root = getComputedStyle(document.documentElement);
        type Rgba = [number, number, number, number];
        const parseColor = (value: string): Rgba => {
          const channels = value.match(/[\d.]+/g)?.map(Number) ?? [];
          return [channels[0] ?? 0, channels[1] ?? 0, channels[2] ?? 0, channels[3] ?? 1];
        };
        const composite = (foreground: Rgba, background: Rgba): Rgba => {
          const alpha = foreground[3] + background[3] * (1 - foreground[3]);
          if (alpha === 0) return [0, 0, 0, 0];
          return [
            (foreground[0] * foreground[3] + background[0] * background[3] * (1 - foreground[3])) / alpha,
            (foreground[1] * foreground[3] + background[1] * background[3] * (1 - foreground[3])) / alpha,
            (foreground[2] * foreground[3] + background[2] * background[3] * (1 - foreground[3])) / alpha,
            alpha,
          ];
        };
        const effectiveBackground = (element: HTMLElement): Rgba => {
          const layers: Rgba[] = [];
          let current: HTMLElement | null = element;
          while (current) {
            layers.push(parseColor(getComputedStyle(current).backgroundColor));
            current = current.parentElement;
          }
          return layers.reverse().reduce(
            (background, foreground) => composite(foreground, background),
            [255, 255, 255, 1] as Rgba,
          );
        };
        const luminance = (channels: Rgba) => {
          const linear = channels.slice(0, 3).map((channel) => {
            const normalized = channel / 255;
            return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * linear[0]! + 0.7152 * linear[1]! + 0.0722 * linear[2]!;
        };
        const contrast = (foreground: Rgba, background: Rgba) => {
          const light = Math.max(luminance(foreground), luminance(background));
          const dark = Math.min(luminance(foreground), luminance(background));
          return (light + 0.05) / (dark + 0.05);
        };
        const semanticPills = Array.from(
          document.querySelectorAll<HTMLElement>(
            ".state-pill--healthy, .state-pill--succeeded, .state-pill--attention, .state-pill--failed",
          ),
        );
        const dangerProbe = document.createElement("span");
        dangerProbe.className = "state-pill state-pill--failed";
        dangerProbe.textContent = "failed";
        dangerProbe.style.position = "absolute";
        dangerProbe.style.left = "-10000px";
        document.querySelector<HTMLElement>(".project-stat")!.append(dangerProbe);
        semanticPills.push(dangerProbe);
        const semanticPillContrasts = semanticPills.map(
          (pill) => {
            const style = getComputedStyle(pill);
            return contrast(parseColor(style.color), effectiveBackground(pill));
          },
        );
        dangerProbe.remove();
        return {
          theme: document.documentElement.dataset.theme,
          mode: document.documentElement.dataset.mode,
          scheme: document.documentElement.style.colorScheme,
          page: getComputedStyle(workspace).backgroundColor,
          chrome: getComputedStyle(sidebar).backgroundColor,
          separator: getComputedStyle(separator).backgroundColor,
          surface: getComputedStyle(surface).backgroundColor,
          accent: root.getPropertyValue("--pam-ice").trim(),
          font: getComputedStyle(title).fontFamily,
          art: getComputedStyle(art).backgroundImage,
          semanticPillContrasts,
        };
      });

      expect(computed).toMatchObject({
        theme: appearance.theme,
        mode: appearance.mode,
        scheme: appearance.mode,
        page: appearance.page,
        surface: appearance.surface,
        accent: appearance.accent,
      });
      expect(computed.font).toContain(appearance.font);
      expect(computed.art).toContain(appearance.asset);
      expect(computed.separator).toBe(computed.chrome);
      expect(computed.semanticPillContrasts.length).toBeGreaterThan(0);
      expect(Math.min(...computed.semanticPillContrasts)).toBeGreaterThanOrEqual(4.5);
      await expect(page).toHaveScreenshot(`theme-${appearance.theme}-${appearance.mode}-1180x800.png`);
    });
  }

  test("switches family and variant with Radix controls and restores both on reload", async ({ page }) => {
    await page.setViewportSize({ width: 1_180, height: 800 });
    await openFixture(page);
    const trigger = page.getByRole("button", { name: "Theme: Ventisquero · light" });

    await trigger.click();
    await page.getByRole("menuitemradio", { name: /^Viña del Mar/ }).click();
    await page.getByRole("button", { name: "Theme: Viña del Mar · light" }).click();
    await page.getByRole("menuitemradio", { name: /^Dark/ }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "vina");
    await expect(page.locator("html")).toHaveAttribute("data-mode", "dark");

    await page.reload();
    await page.locator(".app-shell").waitFor();
    await expect(page.getByRole("button", { name: "Theme: Viña del Mar · dark" })).toBeVisible();
    await page.getByRole("button", { name: "Theme: Viña del Mar · dark" }).click();
    await expect(page.getByRole("menuitemradio", { name: /^Viña del Mar/ })).toBeChecked();
    await expect(page.getByRole("menuitemradio", { name: /^Dark/ })).toBeChecked();
    await expect(page).toHaveScreenshot("theme-menu-vina-dark-1180x800.png");
  });
});

test.describe("Access skill audit", () => {
  test("preserves the shell and renders the evaluated audit truth at 1180px", async ({ page }) => {
    await page.setViewportSize({ width: 1_180, height: 1_000 });
    await openFixture(page, "solved", "access");
    await expect(page.getByRole("heading", { name: "Evaluator verdict" })).toBeVisible();

    const navigationLabels = await page.getByRole("navigation", { name: "Primary" })
      .getByRole("button")
      .evaluateAll((buttons) => buttons.map((button) => button.getAttribute("aria-label")));
    expect(navigationLabels).toEqual(["Current", "Flows", "Access"]);
    const geometry = await page.evaluate(() => {
      const width = (selector: string) => document.querySelector<HTMLElement>(selector)?.getBoundingClientRect().width ?? -1;
      const workspace = document.querySelector<HTMLElement>(".workspace")?.getBoundingClientRect();
      const toolbar = document.querySelector<HTMLElement>(".toolbar")?.getBoundingClientRect();
      return {
        sidebar: width(".sidebar"),
        separator: width(".resize-separator"),
        toolbar: toolbar?.height ?? -1,
        workspaceRight: workspace?.right ?? -1,
      };
    });
    expect(geometry).toEqual({ sidebar: 248, separator: 5, toolbar: 52, workspaceRight: 1_170 });

    const ranked = page.getByRole("region", { name: "Ranked artifacts" });
    const verdict = page.getByRole("region", { name: "Evaluator verdict" });
    await expect(ranked.getByText("Project instructions")).toBeVisible();
    await expect(ranked.getByText("AGENTS.md")).toBeVisible();
    await expect(verdict.getByText("codex", { exact: true })).toBeVisible();
    await expect(verdict.getByText("elevated", { exact: true }).first()).toBeVisible();
    await expect(page.getByRole("heading", { name: "Overlaps" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Conflicts" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Stale candidates" })).toBeVisible();
    await page.locator(".skill-audit-panel").scrollIntoViewIfNeeded();
    await expect(page).toHaveScreenshot("access-audit-evaluated-1180x1000.png");
  });

  test("keeps Run and Retry audit actions reachable at effective 320px", async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 800 });
    await openFixture(page, "skill-audit-empty", "access");
    const run = page.getByRole("button", { name: "Run audit" });
    await run.scrollIntoViewIfNeeded();
    await expect(run).toBeVisible();
    const runBox = await run.boundingBox();
    expect(runBox).not.toBeNull();
    expect(runBox!.x).toBeGreaterThanOrEqual(0);
    expect(runBox!.x + runBox!.width).toBeLessThanOrEqual(320);
    let horizontal = await horizontalMetrics(page);
    expect(horizontal.htmlScroll).toBe(horizontal.htmlClient);
    expect(horizontal.bodyScroll).toBe(horizontal.bodyClient);
    expect(horizontal.shellScroll).toBe(horizontal.shellClient);

    await openFixture(page, "skill-audit-load-error", "access");
    const retry = page.getByRole("button", { name: "Retry audit" });
    await retry.scrollIntoViewIfNeeded();
    await expect(retry).toBeVisible();
    const retryBox = await retry.boundingBox();
    expect(retryBox).not.toBeNull();
    expect(retryBox!.x).toBeGreaterThanOrEqual(0);
    expect(retryBox!.x + retryBox!.width).toBeLessThanOrEqual(320);
    horizontal = await horizontalMetrics(page);
    expect(horizontal.htmlScroll).toBe(horizontal.htmlClient);
    expect(horizontal.bodyScroll).toBe(horizontal.bodyClient);
    expect(horizontal.shellScroll).toBe(horizontal.shellClient);
  });

  test("shows deterministic footprint fallback without a qualitative verdict", async ({ page }) => {
    await page.setViewportSize({ width: 1_180, height: 800 });
    await openFixture(page, "skill-audit-no-evaluator", "access");

    await expect(page.getByText(
      "Deterministic footprint only — no supported evaluator was available, so PAM did not produce a qualitative verdict.",
    )).toBeVisible();
    await expect(page.getByRole("heading", { name: "Evaluator verdict" })).toHaveCount(0);
    await expect(page.getByText("Saturation grade")).toHaveCount(0);
  });
});

test.describe("Access skill library", () => {
  test("keeps exact target identity through drift, resync, and refreshed mutation truth", async ({ page }) => {
    await page.setViewportSize({ width: 1_180, height: 1_000 });
    await openFixture(page, "solved", "access");
    const panel = page.getByRole("region", { name: "Skill library" });
    await expect(panel).toBeVisible();
    await expect(panel.getByText("Git install · commit")).toBeVisible();
    await expect(panel.getByText("Local install · source path not retained")).toBeVisible();
    await expect(panel.getByText("not inspected").first()).toBeVisible();

    await panel.getByRole("combobox", { name: "Library entry" }).selectOption("review-changes");
    await panel.getByRole("combobox", { name: "Library agent" }).selectOption("cursor");
    await panel.getByRole("button", { name: "Inspect drift" }).click();
    const inspection = panel.getByRole("region", { name: "Verified drift inspection" });
    await expect(inspection).toBeVisible();
    await expect(inspection.getByText("modified", { exact: true })).toBeVisible();

    await panel.getByRole("button", { name: "Preview resync" }).click();
    const preview = panel.getByRole("region", { name: "Verified resync preview" });
    await expect(preview).toBeVisible();
    await expect(preview.getByText("replace", { exact: true })).toBeVisible();
    await expect(preview.getByText("Backup planned before replacement")).toBeVisible();
    await preview.getByRole("button", { name: "Apply exact resync" }).click();
    await expect(panel.getByText("Resync verified against refreshed library state.")).toBeVisible();
    await expect(preview).toHaveCount(0);
    let result = panel.getByRole("region", { name: "Verified operation result" });
    await expect(result.getByText("Ownership recorded: yes")).toBeVisible();
    await expect(result.getByText(/Backup: 1024 bytes/)).toBeVisible();

    await panel.getByRole("button", { name: "Disable target" }).click();
    await expect(panel.getByText("Disablement verified against refreshed library state.")).toBeVisible();
    result = panel.getByRole("region", { name: "Verified operation result" });
    await expect(result.getByText("removed", { exact: true })).toBeVisible();
    await panel.getByRole("button", { name: "Enable target" }).click();
    await expect(panel.getByText("Enablement verified against refreshed library state.")).toBeVisible();
    result = panel.getByRole("region", { name: "Verified operation result" });
    await expect(result.getByText("yes", { exact: true })).toHaveCount(2);

    await panel.getByLabel("Library entry ID", { exact: true }).first().fill("adopted-review");
    await panel.getByLabel("Observed inventory artifact").selectOption("artifact:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    await panel.getByRole("button", { name: "Adopt into library" }).click();
    await expect(panel.getByText("Adoption verified against refreshed library state.")).toBeVisible();
    await expect(panel.getByRole("region", { name: "Verified operation result" }).getByText("inserted", { exact: true })).toBeVisible();
    await expect(panel.getByLabel("Canonical library entries").getByText("adopted-review")).toBeVisible();
  });

  test("keeps every library form and preview/apply action reachable at effective 320px", async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 800 });
    await openFixture(page, "solved", "access");
    const panel = page.getByRole("region", { name: "Skill library" });
    await panel.scrollIntoViewIfNeeded();

    for (const name of [
      "Adopt into library",
      "Install into library",
      "Enable target",
      "Inspect drift",
    ]) {
      const action = panel.getByRole("button", { name });
      await action.scrollIntoViewIfNeeded();
      await expect(action).toBeVisible();
      const box = await action.boundingBox();
      expect(box).not.toBeNull();
      expect(box!.x).toBeGreaterThanOrEqual(0);
      expect(box!.x + box!.width).toBeLessThanOrEqual(320);
    }

    await panel.getByRole("combobox", { name: "Library entry" }).selectOption("review-changes");
    await panel.getByRole("combobox", { name: "Library agent" }).selectOption("cursor");
    await panel.getByRole("button", { name: "Preview resync" }).click();
    const apply = panel.getByRole("button", { name: "Apply exact resync" });
    await apply.scrollIntoViewIfNeeded();
    await expect(apply).toBeVisible();
    const applyBox = await apply.boundingBox();
    expect(applyBox).not.toBeNull();
    expect(applyBox!.x).toBeGreaterThanOrEqual(0);
    expect(applyBox!.x + applyBox!.width).toBeLessThanOrEqual(320);

    const horizontal = await horizontalMetrics(page);
    expect(horizontal.htmlScroll).toBe(horizontal.htmlClient);
    expect(horizontal.bodyScroll).toBe(horizontal.bodyClient);
    expect(horizontal.shellScroll).toBe(horizontal.shellClient);
  });
});
