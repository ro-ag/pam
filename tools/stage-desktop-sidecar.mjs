#!/usr/bin/env node

import { chmod, copyFile, mkdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const supportedTargets = new Set([
  "aarch64-apple-darwin",
  "aarch64-pc-windows-msvc",
  "aarch64-unknown-linux-gnu",
  "x86_64-pc-windows-msvc",
  "x86_64-unknown-linux-gnu",
]);

const target = process.argv[2];
if (!supportedTargets.has(target)) {
  console.error(`usage: stage-desktop-sidecar.mjs <${[...supportedTargets].join("|")}>`);
  process.exit(2);
}

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repository = resolve(scriptDirectory, "..");
if (
  target === "aarch64-apple-darwin" &&
  process.env.MACOSX_DEPLOYMENT_TARGET &&
  process.env.MACOSX_DEPLOYMENT_TARGET !== "12.0"
) {
  console.error("MACOSX_DEPLOYMENT_TARGET must be 12.0 for the supported macOS preview");
  process.exit(2);
}
const buildEnvironment = target === "aarch64-apple-darwin"
  ? { ...process.env, MACOSX_DEPLOYMENT_TARGET: "12.0" }
  : process.env;
const cargo = spawnSync(
  "cargo",
  ["build", "--release", "--locked", "--target", target, "-p", "pam_cli", "--bin", "pam"],
  { cwd: repository, env: buildEnvironment, stdio: "inherit" },
);
if (cargo.status !== 0) process.exit(cargo.status ?? 1);

const metadata = spawnSync(
  "cargo",
  ["metadata", "--no-deps", "--format-version", "1"],
  { cwd: repository, encoding: "utf8" },
);
if (metadata.status !== 0) {
  process.stderr.write(metadata.stderr);
  process.exit(metadata.status ?? 1);
}

const targetDirectory = JSON.parse(metadata.stdout).target_directory;
const extension = target.includes("windows") ? ".exe" : "";
const source = join(targetDirectory, target, "release", `pam${extension}`);
const destination = join(repository, "src-tauri", "binaries", `pam-${target}${extension}`);
await mkdir(dirname(destination), { recursive: true });
await copyFile(source, destination);
if (!extension) await chmod(destination, 0o755);
console.log(`staged ${destination}`);
