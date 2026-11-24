import { expect, test } from "@playwright/test";
import path from "node:path";
import { analyze, exampleZip, textFile, upload } from "./helpers.js";

const shots = process.env.E2E_SCREENSHOT_DIR;
async function shot(page, name) {
  if (shots) await page.screenshot({ path: path.join(shots, `${name}.png`), fullPage: true });
}

test.beforeEach(async ({ page }) => {
  await page.goto("/");
});

test("shows the empty state and what the server can do", async ({ page }) => {
  await expect(page.getByTestId("empty")).toContainText("Will this upgrade break your project?");
  const health = page.getByTestId("health");
  await expect(health).toContainText("Prolog engine");
  await expect(health).toContainText("hybrid classifier");
  await expect(health).toContainText("parallel");
  await expect(page.getByTestId("dropzone")).toBeVisible();
  await shot(page, "01-empty");
});

test("pandas 1.5.3 to 2.0.0: finds the removed API in the project", async ({ page }) => {
  await upload(page, exampleZip("pandas_append_project"));

  // The form is filled in from the project's own requirements.txt.
  await expect(page.getByTestId("project")).toContainText("pandas_append_project");
  await expect(page.getByTestId("project")).toContainText("1 source · 1 test file");
  await expect(page.getByTestId("dependency")).toContainText("pandas");
  await expect(page.getByTestId("dependency")).toContainText("==1.5.3");
  await expect(page.getByTestId("package-input")).toHaveValue("pandas");
  await expect(page.getByTestId("current-version")).toHaveValue("1.5.3");

  // The target defaults to a newer release and never offers an older one.
  const target = page.getByTestId("target-version");
  await expect(target).not.toHaveValue("");
  await expect(target.locator('option[value="1.5.2"]')).toHaveCount(0);
  await expect(target.locator('option[value="1.5.3"]')).toHaveCount(0);
  await shot(page, "02-form");

  await analyze(page, { current: "1.5.3", target: "2.0.0" });

  const report = page.getByTestId("report");
  await expect(report).toBeVisible({ timeout: 180_000 });
  await expect(page.getByTestId("report-title")).toContainText("pandas");
  await expect(page.getByTestId("report-title")).toContainText("1.5.3 → 2.0.0");
  await expect(page.getByTestId("engine")).toHaveText("Prolog inference");

  await expect(page.getByTestId("migration-risk")).toHaveAttribute("data-level", "high");
  await expect(page.getByTestId("migration-risk")).toContainText("removed used api");
  await expect(page.getByTestId("migration-risk")).toContainText("pandas.DataFrame.append");
  await expect(page.getByTestId("upgrade-urgency")).toHaveAttribute("data-level", "low");

  const usage = page.getByTestId("affected-usage").first();
  await expect(usage).toContainText("src/report.py:6");
  await expect(usage).toContainText("pandas.DataFrame.append");
  await expect(usage).toContainText("removed");
  const hit = usage.locator(".code-hit");
  await expect(hit).toHaveCount(1);
  await expect(hit).toContainText("frame.append");
  await expect(hit.locator(".code-no")).toHaveText("6");

  await expect(page.getByTestId("actions")).toContainText("Replace pandas.DataFrame.append");
  await expect(page.getByTestId("tests")).toContainText("tests/test_report.py");
  await expect(page.getByTestId("findings")).toContainText("removed_used_api");
  await expect(page.getByTestId("note").first()).toBeVisible();

  // The job row carries the verdict too.
  const job = page.getByTestId("job").first();
  await expect(job).toHaveAttribute("data-status", "done");
  await expect(job).toContainText("risk high");
  await shot(page, "03-pandas-report");
});

test("requests 2.28.0 to 2.32.0: urgent but safe, with advisories", async ({ page }) => {
  await upload(page, exampleZip("requests_security_project"));
  await expect(page.getByTestId("current-version")).toHaveValue("2.28.0");
  await analyze(page, { current: "2.28.0", target: "2.32.0" });

  await expect(page.getByTestId("report")).toBeVisible({ timeout: 180_000 });
  await expect(page.getByTestId("migration-risk")).toHaveAttribute("data-level", "low");
  await expect(page.getByTestId("upgrade-urgency")).toHaveAttribute("data-level", "high");
  await expect(page.getByTestId("affected")).toHaveCount(0);

  const fixed = page.getByTestId("vuln-fixed");
  await expect(fixed).toContainText("GHSA-9wx4-h78v-vm56");
  await expect(fixed).toContainText("GHSA-j8r2-6x86-q33q");
  await expect(page.getByTestId("vuln-remaining")).not.toContainText("GHSA-9wx4-h78v-vm56");
  await expect(page.getByTestId("actions")).toContainText("Upgrade to requests 2.32.0");

  // Filtering release notes by category only leaves that category.
  await page.getByTestId("filter-security_fix").click();
  const notes = page.getByTestId("note");
  await expect(notes.first()).toBeVisible();
  const categories = await notes.evaluateAll((items) => items.map((item) => item.dataset.category));
  expect(categories.length).toBeGreaterThan(0);
  expect(new Set(categories)).toEqual(new Set(["security_fix"]));
  await expect(notes.first()).toContainText("rule:");
  await shot(page, "04-requests-report");
});

test("several analyses run at the same time", async ({ page }) => {
  await upload(page, exampleZip("pandas_append_project"));
  const targets = ["2.0.1", "2.0.2", "2.0.3"];
  for (const target of targets) {
    await analyze(page, { current: "1.5.3", target });
  }

  const jobs = page.getByTestId("job");
  await expect(jobs).toHaveCount(3);
  // All three were accepted before any had finished.
  const statuses = await jobs.evaluateAll((items) => items.map((item) => item.dataset.status));
  expect(statuses.filter((status) => status !== "done").length).toBeGreaterThanOrEqual(2);
  await expect(page.getByTestId("job-list")).toContainText("in progress");
  await shot(page, "05-parallel-running");

  await expect(page.locator('[data-testid="job"][data-status="done"]')).toHaveCount(3, {
    timeout: 220_000,
  });

  // Each row opens its own report.
  for (const target of targets) {
    await jobs.filter({ hasText: `1.5.3 → ${target}` }).click();
    await expect(page.getByTestId("report-title")).toContainText(`1.5.3 → ${target}`);
    await expect(page.getByTestId("migration-risk")).toHaveAttribute("data-level", "high");
  }
  await shot(page, "06-parallel-done");
});

test("a repeated request reuses the finished result", async ({ page }) => {
  await upload(page, exampleZip("pandas_append_project"));
  await analyze(page, { current: "1.5.3", target: "2.0.0" });
  await expect(page.getByTestId("report")).toBeVisible({ timeout: 180_000 });

  await page.getByTestId("analyze").click();
  await expect(page.getByTestId("notice")).toContainText("Already analyzed");
  await expect(page.getByTestId("job")).toHaveCount(1);
});

test("finished analyses survive a reload and can be removed", async ({ page }) => {
  await upload(page, exampleZip("requests_security_project"));
  await analyze(page, { current: "2.28.0", target: "2.32.0" });
  await expect(page.getByTestId("report")).toBeVisible({ timeout: 180_000 });

  await page.reload();
  await expect(page.getByTestId("job")).toHaveCount(1);
  await expect(page.getByTestId("report-title")).toContainText("2.28.0 → 2.32.0");

  await page.getByTestId("job").hover();
  await page.getByRole("button", { name: "Remove from list" }).click();
  await expect(page.getByTestId("job")).toHaveCount(0);
  await expect(page.getByTestId("empty")).toBeVisible();
  await page.reload();
  await expect(page.getByTestId("job")).toHaveCount(0);
});

test("rejects files that are not project archives", async ({ page }) => {
  await page.getByTestId("file-input").setInputFiles(textFile("notes.txt", "hello"));
  await expect(page.getByTestId("upload-error")).toContainText(".zip");

  await page.getByTestId("file-input").setInputFiles(textFile("broken.zip", "not really a zip"));
  await expect(page.getByTestId("upload-error")).toContainText("not a valid ZIP");
  await expect(page.getByTestId("dropzone")).toBeVisible();
});

test("an unknown package falls back to typing versions by hand", async ({ page }) => {
  await upload(page, exampleZip("pandas_append_project"));
  await page.getByTestId("package-input").fill("ephemeral-scope-no-such-package-xyz");
  await expect(page.getByTestId("version-error")).toContainText("no package named");
  await expect(page.getByTestId("analyze")).toBeDisabled();

  // Downgrades are refused by the server with a readable message.
  await page.getByTestId("current-version").fill("2.0.0");
  await page.getByTestId("target-version").fill("1.0.0");
  await page.getByTestId("analyze").click();
  await expect(page.getByTestId("submit-error")).toContainText("must be newer");
  await expect(page.getByTestId("job")).toHaveCount(0);

  // Choosing the declared dependency again restores the pickers.
  await page.getByTestId("dependency").click();
  await expect(page.getByTestId("current-version")).toHaveValue("1.5.3");
  await page.getByTestId("replace-project").click();
  await expect(page.getByTestId("dropzone")).toBeVisible();
});

test("the report fits a phone screen", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await upload(page, exampleZip("pandas_append_project"));
  await analyze(page, { current: "1.5.3", target: "2.0.0" });
  await expect(page.getByTestId("report")).toBeVisible({ timeout: 180_000 });
  await expect(page.getByTestId("affected-usage").first()).toBeVisible();

  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
  await shot(page, "07-mobile");
});
