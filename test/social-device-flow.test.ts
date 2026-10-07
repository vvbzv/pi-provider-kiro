import { writeFileSync } from "node:fs";
import type { OAuthLoginCallbacks } from "@earendil-works/pi-ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { KiroCredentials } from "../src/oauth.js";
import { runSocialDeviceFlow, SOCIAL_AUTH_SERVICE_URL } from "../src/social-device-flow.js";

function makeCallbacks() {
  return {
    onAuth: vi.fn(),
    onDeviceCode: vi.fn(),
    onPrompt: vi.fn(),
    onProgress: vi.fn(),
    onSelect: vi.fn(),
    signal: new AbortController().signal,
  } as unknown as OAuthLoginCallbacks & {
    onAuth: ReturnType<typeof vi.fn>;
    onDeviceCode: ReturnType<typeof vi.fn>;
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function authorizationBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    deviceCode: "device-code-1",
    userCode: "ABCD-EFGH",
    verificationUri: "https://app.kiro.dev/account/device",
    verificationUriComplete: "https://app.kiro.dev/account/device?user_code=ABCD-EFGH&login_provider=Google",
    expiresInMilliseconds: 30_000,
    intervalInMilliseconds: 250,
    ...overrides,
  };
}

const authorizedBody = {
  status: "authorized",
  accessToken: "access-token",
  refreshToken: "refresh-token",
  expiresIn: 3600,
  profileArn: "arn:aws:codewhisperer:us-east-1:123456789012:profile/social",
};

describe("runSocialDeviceFlow", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("starts authorization, polls through pending, and returns desktop credentials", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(authorizationBody()))
      .mockResolvedValueOnce(jsonResponse({ status: "authorization_pending" }))
      .mockResolvedValueOnce(jsonResponse(authorizedBody));
    vi.stubGlobal("fetch", fetchMock);
    const callbacks = makeCallbacks();

    const creds = (await runSocialDeviceFlow(callbacks, "google")) as KiroCredentials;

    const [authUrl, authInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(authUrl).toBe(`${SOCIAL_AUTH_SERVICE_URL}/oauth/device/authorization`);
    expect(JSON.parse(String(authInit.body))).toEqual({ clientId: "Kiro-CLI", loginProvider: "Google" });
    const [pollUrl, pollInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(pollUrl).toBe(`${SOCIAL_AUTH_SERVICE_URL}/oauth/device/poll`);
    expect(JSON.parse(String(pollInit.body))).toEqual({ deviceCode: "device-code-1", clientId: "Kiro-CLI" });

    expect(creds.authMethod).toBe("desktop");
    expect(creds.access).toBe("access-token");
    expect(creds.refresh).toBe("refresh-token|desktop");
    expect(creds.profileArn).toBe(authorizedBody.profileArn);
    expect(callbacks.onDeviceCode).toHaveBeenCalledWith(
      expect.objectContaining({ userCode: "ABCD-EFGH", verificationUri: "https://app.kiro.dev/account/device" }),
    );
    expect(callbacks.onAuth).toHaveBeenCalledWith(
      expect.objectContaining({ url: expect.stringContaining("user_code=ABCD-EFGH") }),
    );
  });

  it("spells GitHub the way the auth service expects", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(authorizationBody()))
      .mockResolvedValueOnce(jsonResponse({ ...authorizedBody, profileArn: undefined }));
    vi.stubGlobal("fetch", fetchMock);

    await runSocialDeviceFlow(makeCallbacks(), "github");

    const [, authInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(authInit.body))).toEqual({ clientId: "Kiro-CLI", loginProvider: "Github" });
  });

  it("rejects when the device code expires before approval", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(authorizationBody({ expiresInMilliseconds: 600 })))
      .mockImplementation(() => Promise.resolve(jsonResponse({ status: "authorization_pending" })));
    vi.stubGlobal("fetch", fetchMock);

    await expect(runSocialDeviceFlow(makeCallbacks(), "google")).rejects.toThrow(/Timed out/);
  });

  it("rejects when the service reports expired_token", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(authorizationBody()))
      .mockResolvedValueOnce(jsonResponse({ status: "expired_token" }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(runSocialDeviceFlow(makeCallbacks(), "google")).rejects.toThrow(/expired/);
  });

  it("rejects a malformed authorization response", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse(authorizationBody({ deviceCode: undefined })));
    vi.stubGlobal("fetch", fetchMock);

    await expect(runSocialDeviceFlow(makeCallbacks(), "google")).rejects.toThrow(/deviceCode/);
  });
});

/**
 * Real end-to-end login. Run with KIRO_LIVE_LOGIN=1 and approve the printed URL in a
 * browser (any device — that is the point of the flow). test/setup.ts gives each test
 * file a throwaway HOME, so a developer's kiro-cli store is never touched.
 */
describe.skipIf(process.env.KIRO_LIVE_LOGIN !== "1")("live device login", () => {
  it("completes a real Google device flow and refreshes the token", async () => {
    const callbacks = makeCallbacks();
    let userCode = "";
    callbacks.onDeviceCode.mockImplementation((info: { userCode: string }) => {
      userCode = info.userCode;
    });
    callbacks.onAuth.mockImplementation((info: { url: string }) => {
      writeFileSync("/tmp/kiro-live-device.json", JSON.stringify({ userCode, url: info.url }));
      console.log(`LIVE DEVICE URL: ${info.url}`);
    });

    const creds = (await runSocialDeviceFlow(callbacks, "google")) as KiroCredentials;
    expect(creds.authMethod).toBe("desktop");
    expect(creds.access).toBeTruthy();
    expect(creds.refresh.endsWith("|desktop")).toBe(true);

    // Prove the credential is usable end to end: refresh it against the real service.
    const { refreshKiroToken } = await import("../src/oauth.js");
    const refreshed = (await refreshKiroToken(creds)) as KiroCredentials;
    expect(refreshed.access).toBeTruthy();
  }, 600_000);
});
