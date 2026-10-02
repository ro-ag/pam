// Starts a development `pam gui` with the development-frontend opt-in set.
//
// A `pam gui` built without its embedded frontend refuses to start unless
// PAM_GUI_DEV=1 (crates/pam_gui/src/frontend.rs). The npm scripts used to set
// it with a POSIX `VAR=1 command` prefix, which Windows `cmd` (what `npm run`
// uses there) does not understand. This sets it in the child's environment
// instead, the same way on every platform. Development only: release builds
// never read the variable.
//
//   node scripts/gui-dev.mjs gui       cargo run -p pam -- gui
//   node scripts/gui-dev.mjs desktop   tauri dev -- -- gui   (in crates/pam)

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const modes = {
  gui: { command: "cargo", args: ["run", "-p", "pam", "--", "gui"], cwd: "." },
  desktop: { command: "tauri", args: ["dev", "--", "--", "gui"], cwd: "../crates/pam" },
};

const mode = modes[process.argv[2]];
if (!mode) {
  console.error(`usage: node scripts/gui-dev.mjs <${Object.keys(modes).join("|")}>`);
  process.exit(2);
}

const child = spawn(mode.command, mode.args, {
  // Relative to frontend/, wherever npm was started from.
  cwd: fileURLToPath(new URL(`../${mode.cwd}/`, import.meta.url)),
  env: { ...process.env, PAM_GUI_DEV: "1" },
  stdio: "inherit",
  // `tauri` is a .cmd shim on Windows, which only a shell can start. The
  // command line is the constant above; nothing from outside reaches it.
  shell: process.platform === "win32",
});
child.on("error", (error) => {
  console.error(`cannot start ${mode.command}: ${error.message}`);
  process.exit(1);
});
child.on("exit", (code, signal) => {
  process.exit(signal ? 1 : (code ?? 1));
});
