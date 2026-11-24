import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const repoRoot = path.resolve(here, "..", "..");

const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "ephemeral-scope-e2e-"));

/** Zip one of the example projects, the way a user would before uploading. */
export function exampleZip(name) {
  const target = path.join(workDir, `${name}.zip`);
  if (!fs.existsSync(target)) {
    execFileSync("zip", ["-qr", target, name, "-x", "*__pycache__*"], {
      cwd: path.join(repoRoot, "examples"),
    });
  }
  return target;
}

export function textFile(name, content) {
  const target = path.join(workDir, name);
  fs.writeFileSync(target, content);
  return target;
}

/** Upload a ZIP and wait for the form that follows. */
export async function upload(page, file) {
  await page.getByTestId("file-input").setInputFiles(file);
  await page.getByTestId("analysis-form").waitFor();
}

/** Pick versions once PyPI has answered, then queue the analysis. */
export async function analyze(page, { packageName, current, target }) {
  if (packageName) {
    await page.getByTestId("package-input").fill(packageName);
  }
  const currentSelect = page.getByTestId("current-version");
  await currentSelect.locator(`option[value="${current}"]`).waitFor({ state: "attached", timeout: 30_000 });
  await currentSelect.selectOption(current);
  const targetSelect = page.getByTestId("target-version");
  await targetSelect.locator(`option[value="${target}"]`).waitFor({ state: "attached", timeout: 30_000 });
  await targetSelect.selectOption(target);
  await page.getByTestId("analyze").click();
}
