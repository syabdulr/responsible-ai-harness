/**
 * One-time local setup / rotation / removal of the Jev API key in the
 * macOS Keychain, service `responsible-ai-harness-jev`, account = current
 * OS username. `npm run assess:jev-live` reads it back via
 * `src/judges/jev-local-secret-provider.ts` (env var takes precedence when set).
 *
 * `set` never reads the key into THIS process at all: `security`'s own
 * `-w` flag, given as the very last argument with no value, makes the
 * `security` binary itself prompt on the terminal (hidden input) and
 * store what you type directly — this script's own memory, argv, and
 * logs never contain the key. `remove` and `status` never display the
 * key either (`status` only reports presence/absence).
 *
 * Usage:
 *   npm run jev:secret:set      (also rotates — safe to re-run)
 *   npm run jev:secret:remove
 *   npm run jev:secret:status
 */

import { spawnSync } from "node:child_process";
import { userInfo } from "node:os";
import { JEV_KEYCHAIN_SERVICE } from "../src/judges/jev-local-secret-provider.ts";

function requireMacOS(): void {
  if (process.platform !== "darwin") {
    console.error(
      "This command manages the macOS Keychain and only runs on macOS.\n" +
      "On other platforms (or CI), set TYPESAFE_API_KEY in your environment or secret manager instead — " +
      "npm run assess:jev-live already prefers that env var when it is set.",
    );
    process.exit(1);
  }
}

function account(): string {
  return userInfo().username;
}

function set(): void {
  requireMacOS();
  const acct = account();
  console.log(`Storing (or rotating) the Jev API key in macOS Keychain.`);
  console.log(`  service: ${JEV_KEYCHAIN_SERVICE}`);
  console.log(`  account: ${acct}`);
  console.log(`"security" will prompt you directly on this terminal for the key — this script never sees or stores it itself.\n`);
  const result = spawnSync(
    "security",
    ["add-generic-password", "-a", acct, "-s", JEV_KEYCHAIN_SERVICE, "-U", "-w"],
    { stdio: "inherit" },
  );
  if (result.status !== 0) {
    console.error("\nFailed to store the key in Keychain.");
    process.exit(result.status ?? 1);
  }
  console.log("\nStored. Verify with: npm run jev:secret:status");
}

function remove(): void {
  requireMacOS();
  const acct = account();
  const result = spawnSync("security", ["delete-generic-password", "-a", acct, "-s", JEV_KEYCHAIN_SERVICE], { stdio: "inherit" });
  if (result.status !== 0) {
    console.error(`\nNo key found to remove for service "${JEV_KEYCHAIN_SERVICE}", account "${acct}" (or deletion failed).`);
    process.exit(result.status ?? 1);
  }
  console.log("\nRemoved.");
}

function status(): void {
  requireMacOS();
  const acct = account();
  const result = spawnSync("security", ["find-generic-password", "-a", acct, "-s", JEV_KEYCHAIN_SERVICE], { stdio: "ignore" });
  if (result.status === 0) {
    console.log(`A Jev API key IS stored in Keychain (service "${JEV_KEYCHAIN_SERVICE}", account "${acct}"). Value not displayed.`);
  } else {
    console.log(`No Jev API key is stored in Keychain (service "${JEV_KEYCHAIN_SERVICE}", account "${acct}").`);
  }
}

function main(): void {
  const cmd = process.argv[2];
  if (cmd === "set") return set();
  if (cmd === "remove") return remove();
  if (cmd === "status") return status();
  console.error("Usage: tsx scripts/jev-secret.ts <set|remove|status>\n(or: npm run jev:secret:set / jev:secret:remove / jev:secret:status)");
  process.exit(1);
}

main();
