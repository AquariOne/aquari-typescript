import {
  AquariConfigurationError,
} from "./errors.js";

const PKCE_CODE_VERIFIER_PATTERN =
  /^[A-Za-z0-9._~-]{43,128}$/u;

export interface AquariPkcePair {
  codeVerifier: string;
  codeChallenge: string;
}

export function createSecureRandomValue(
  byteLength: number,
): string {
  if (
    !Number.isInteger(byteLength) ||
    byteLength <= 0
  ) {
    throw new AquariConfigurationError(
      "Secure random byte length must be a positive integer.",
    );
  }

  const bytes =
    new Uint8Array(byteLength);

  globalThis.crypto.getRandomValues(bytes);

  return encodeBase64Url(bytes);
}

export async function createS256CodeChallenge(
  codeVerifier: string,
): Promise<string> {
  if (!PKCE_CODE_VERIFIER_PATTERN.test(codeVerifier)) {
    throw new AquariConfigurationError(
      "PKCE code verifier must contain 43 to 128 RFC 7636 unreserved characters.",
    );
  }

  const digest =
    await globalThis.crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(codeVerifier),
    );

  return encodeBase64Url(
    new Uint8Array(digest),
  );
}

export async function createPkcePair():
Promise<AquariPkcePair> {
  const codeVerifier =
    createSecureRandomValue(48);

  return {
    codeVerifier,
    codeChallenge:
      await createS256CodeChallenge(
        codeVerifier,
      ),
  };
}

function encodeBase64Url(
  bytes: Uint8Array,
): string {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return globalThis
    .btoa(binary)
    .replace(/\+/gu, "-")
    .replace(/\//gu, "_")
    .replace(/=+$/gu, "");
}
