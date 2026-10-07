// ABOUTME: Native Google/GitHub device-code login against Kiro's social auth service.
// ABOUTME: Works headless (SSH, containers, JupyterLab) — no loopback callback, no kiro-cli.

import type { OAuthCredentials, OAuthLoginCallbacks } from "@earendil-works/pi-ai";
import type { KiroCredentials } from "./oauth.js";

/** Kiro's social auth service — the same host the plugin refreshes desktop tokens against. */
export const SOCIAL_AUTH_SERVICE_URL = "https://prod.us-east-1.auth.desktop.kiro.dev";
/** The only client identifier the social path sends; kiro-cli presents the same value. */
export const SOCIAL_CLIENT_ID = "Kiro-CLI";

export type SocialLoginProvider = "google" | "github";

/** Wire spelling the auth service expects ("Github", not "GitHub"). */
const WIRE_PROVIDER: Record<SocialLoginProvider, string> = { google: "Google", github: "Github" };

const JSON_HEADERS: Record<string, string> = {
  "Content-Type": "application/json",
  "User-Agent": SOCIAL_CLIENT_ID,
};

const DEFAULT_EXPIRES_MS = 300_000;
const DEFAULT_INTERVAL_MS = 5_000;
/** Floor so a malformed interval can never turn the poll loop into a hammer. */
const MIN_INTERVAL_MS = 250;

interface DeviceAuthorization {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  expiresAt: number;
  intervalMs: number;
}

type ProgressFn = ((msg: string) => void) | undefined;

function getProgress(callbacks: OAuthLoginCallbacks): ProgressFn {
  return (callbacks as { onProgress?: (msg: string) => void }).onProgress?.bind(callbacks);
}

function getSignal(callbacks: OAuthLoginCallbacks): AbortSignal | undefined {
  return (callbacks as { signal?: AbortSignal }).signal;
}

function requireString(data: Record<string, unknown>, key: string): string {
  const value = data[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Kiro auth service returned a malformed ${key}`);
  }
  return value;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onAbort = () => {
      if (timer) clearTimeout(timer);
      reject(signal?.reason ?? new Error("Login cancelled"));
    };
    if (signal?.aborted) return onAbort();
    timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

async function startDeviceAuthorization(
  provider: SocialLoginProvider,
  signal: AbortSignal | undefined,
): Promise<DeviceAuthorization> {
  const response = await fetch(`${SOCIAL_AUTH_SERVICE_URL}/oauth/device/authorization`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ clientId: SOCIAL_CLIENT_ID, loginProvider: WIRE_PROVIDER[provider] }),
    ...(signal ? { signal } : {}),
  });
  if (!response.ok) {
    throw new Error(`Kiro device authorization failed: ${response.status} ${response.statusText}`);
  }
  const data = (await response.json()) as Record<string, unknown>;
  const expiresInMs = Number(data.expiresInMilliseconds);
  const intervalMs = Number(data.intervalInMilliseconds);
  return {
    deviceCode: requireString(data, "deviceCode"),
    userCode: requireString(data, "userCode"),
    verificationUri: requireString(data, "verificationUri"),
    verificationUriComplete: requireString(data, "verificationUriComplete"),
    expiresAt: Date.now() + (Number.isFinite(expiresInMs) && expiresInMs > 0 ? expiresInMs : DEFAULT_EXPIRES_MS),
    intervalMs:
      Number.isFinite(intervalMs) && intervalMs > 0 ? Math.max(intervalMs, MIN_INTERVAL_MS) : DEFAULT_INTERVAL_MS,
  };
}

/** `authorized` poll payload → the plugin's desktop credential shape. */
function credentialsFromPoll(data: Record<string, unknown>): KiroCredentials {
  const expiresIn = Number(data.expiresIn);
  const ttlSeconds = Number.isFinite(expiresIn) && expiresIn > 0 ? expiresIn : 3600;
  const profileArn = typeof data.profileArn === "string" && data.profileArn ? data.profileArn : undefined;
  return {
    refresh: `${requireString(data, "refreshToken")}|desktop`,
    access: requireString(data, "accessToken"),
    expires: Date.now() + ttlSeconds * 1000 - 5 * 60 * 1000,
    clientId: "",
    clientSecret: "",
    region: "us-east-1",
    authMethod: "desktop",
    ...(profileArn ? { profileArn } : {}),
  };
}

async function pollForCredentials(
  auth: DeviceAuthorization,
  signal: AbortSignal | undefined,
): Promise<KiroCredentials> {
  while (Date.now() < auth.expiresAt) {
    const response = await fetch(`${SOCIAL_AUTH_SERVICE_URL}/oauth/device/poll`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ deviceCode: auth.deviceCode, clientId: SOCIAL_CLIENT_ID }),
      ...(signal ? { signal } : {}),
    });
    if (response.ok) {
      const data = (await response.json()) as Record<string, unknown>;
      const status = typeof data.status === "string" ? data.status : "";
      if (status === "authorized") return credentialsFromPoll(data);
      if (status === "expired_token") throw new Error("Kiro device code expired before approval");
      if (status === "invalid_token") throw new Error("Kiro device code was rejected as invalid");
      // authorization_pending (and unknown statuses) — keep polling until the deadline.
    }
    await sleep(auth.intervalMs, signal);
  }
  throw new Error("Timed out waiting for device approval");
}

/**
 * Google/GitHub login via Kiro's device-code flow.
 *
 * The user approves a code in any browser, so this works on hosts with no browser
 * and no kiro-cli: SSH sessions, containers, JupyterLab/SageMaker.
 */
export async function runSocialDeviceFlow(
  callbacks: OAuthLoginCallbacks,
  provider: SocialLoginProvider,
): Promise<OAuthCredentials> {
  const signal = getSignal(callbacks);
  const progress = getProgress(callbacks);
  const label = WIRE_PROVIDER[provider];

  progress?.(`Requesting a ${label} device code...`);
  const auth = await startDeviceAuthorization(provider, signal);

  // onDeviceCode drives pi's own login dialog; onAuth renders in the extension's
  // waiting overlay (and carries the same URL), so the code is visible either way.
  callbacks.onDeviceCode({
    userCode: auth.userCode,
    verificationUri: auth.verificationUri,
    intervalSeconds: Math.round(auth.intervalMs / 1000),
    expiresInSeconds: Math.max(0, Math.round((auth.expiresAt - Date.now()) / 1000)),
  });
  callbacks.onAuth({
    url: auth.verificationUriComplete,
    instructions: `Open the URL and confirm the code ${auth.userCode}.`,
  });

  const creds = await pollForCredentials(auth, signal);

  progress?.(`${label} login successful`);
  try {
    const { saveKiroCliCredentials } = await import("./kiro-cli.js");
    saveKiroCliCredentials(creds);
  } catch {
    // kiro-cli is optional; pi keeps its own copy of the credential.
  }
  return creds;
}
