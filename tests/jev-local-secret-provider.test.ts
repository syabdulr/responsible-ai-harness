import { describe, expect, it, vi } from "vitest";
import { userInfo } from "node:os";
import { createLocalSecretProvider, JEV_LOCAL_SECRET_REF, JEV_KEYCHAIN_SERVICE } from "../src/judges/jev-local-secret-provider.ts";

/**
 * All secret retrieval is mocked here via an injected `keychainReader` —
 * zero network calls, and the real macOS `security` binary is never
 * spawned by this file.
 */

describe("createLocalSecretProvider — precedence and fail-closed behavior", () => {
  it("prefers TYPESAFE_API_KEY env var over the Keychain when both are present", () => {
    const keychainReader = vi.fn(() => "from-keychain-never-used");
    const provider = createLocalSecretProvider({ env: { TYPESAFE_API_KEY: "from-env" }, keychainReader });
    expect(provider.resolve(JEV_LOCAL_SECRET_REF)).toBe("from-env");
    expect(keychainReader).not.toHaveBeenCalled();
  });

  it("falls back to the Keychain reader when the env var is unset", () => {
    const keychainReader = vi.fn((service: string, account: string) => {
      expect(service).toBe(JEV_KEYCHAIN_SERVICE);
      expect(account).toBe(userInfo().username);
      return "from-keychain";
    });
    const provider = createLocalSecretProvider({ env: {}, keychainReader });
    expect(provider.resolve(JEV_LOCAL_SECRET_REF)).toBe("from-keychain");
    expect(keychainReader).toHaveBeenCalledTimes(1);
  });

  it("falls back to the Keychain reader when the env var is an empty string", () => {
    const keychainReader = vi.fn(() => "from-keychain");
    const provider = createLocalSecretProvider({ env: { TYPESAFE_API_KEY: "" }, keychainReader });
    expect(provider.resolve(JEV_LOCAL_SECRET_REF)).toBe("from-keychain");
  });

  it("returns undefined (fails closed) when neither source has a value", () => {
    const keychainReader = vi.fn(() => undefined);
    const provider = createLocalSecretProvider({ env: {}, keychainReader });
    expect(provider.resolve(JEV_LOCAL_SECRET_REF)).toBeUndefined();
  });

  it("never calls the keychain reader when JEV_SKIP_KEYCHAIN=1 is set", () => {
    const keychainReader = vi.fn(() => "should-never-be-returned");
    const provider = createLocalSecretProvider({ env: { JEV_SKIP_KEYCHAIN: "1" }, keychainReader });
    expect(provider.resolve(JEV_LOCAL_SECRET_REF)).toBeUndefined();
    expect(keychainReader).not.toHaveBeenCalled();
  });

  it("returns undefined for any secretRef other than JEV_LOCAL_SECRET_REF, without consulting the keychain", () => {
    const keychainReader = vi.fn(() => "should-never-be-returned");
    const provider = createLocalSecretProvider({ env: { TYPESAFE_API_KEY: "present" }, keychainReader });
    expect(provider.resolve("some/other/ref")).toBeUndefined();
    expect(keychainReader).not.toHaveBeenCalled();
  });
});
