import {
  AquariConfigurationError,
} from "./errors.js";

import type {
  AquariHttpTransport,
} from "./transport.js";

/**
 * Contains validated OpenID Connect discovery metadata for the configured Aquari issuer.
 */
export interface AquariOidcDiscovery {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userInfoEndpoint: string;
  jwksUri: string;
  grantTypesSupported: readonly string[];
  responseTypesSupported: readonly string[];
  codeChallengeMethodsSupported:
    readonly string[];
  idTokenSigningAlgorithmsSupported:
    readonly string[];
  tokenEndpointAuthMethodsSupported:
    readonly string[];
  authorizationResponseIssuerParameterSupported:
    boolean;
}

/**
 * Configures cancellation for an OIDC discovery request.
 */
export interface AquariDiscoveryOptions {
  signal?: AbortSignal;
}

export async function discoverAquariOidc(
  transport: AquariHttpTransport,
  configuredIssuer: string,
  options: AquariDiscoveryOptions = {},
): Promise<AquariOidcDiscovery> {
  const requestOptions = {
    path:
      "/.well-known/openid-configuration",
    ...(options.signal !== undefined
      ? { signal: options.signal }
      : {}),
  };

  const raw: unknown =
    await transport.request(
      requestOptions,
    );

  if (!isRecord(raw)) {
    throw new AquariConfigurationError(
      "Aquari OIDC discovery returned an invalid document.",
    );
  }

  const issuer =
    readRequiredString(raw, "issuer");

  if (issuer !== configuredIssuer) {
    throw new AquariConfigurationError(
      "Aquari OIDC discovery issuer does not exactly match the configured issuer.",
    );
  }

  const grantTypesSupported =
    readRequiredStringArray(
      raw,
      "grant_types_supported",
    );

  const responseTypesSupported =
    readRequiredStringArray(
      raw,
      "response_types_supported",
    );

  const codeChallengeMethodsSupported =
    readRequiredStringArray(
      raw,
      "code_challenge_methods_supported",
    );

  const idTokenSigningAlgorithmsSupported =
    readRequiredStringArray(
      raw,
      "id_token_signing_alg_values_supported",
    );

  requireValue(
    grantTypesSupported,
    "authorization_code",
    "Aquari OIDC discovery does not advertise the authorization-code grant.",
  );

  requireValue(
    grantTypesSupported,
    "refresh_token",
    "Aquari OIDC discovery does not advertise the refresh-token grant.",
  );

  requireValue(
    responseTypesSupported,
    "code",
    "Aquari OIDC discovery does not advertise the code response type.",
  );

  requireValue(
    codeChallengeMethodsSupported,
    "S256",
    "Aquari OIDC discovery does not advertise S256 PKCE.",
  );

  requireValue(
    idTokenSigningAlgorithmsSupported,
    "RS256",
    "Aquari OIDC discovery does not advertise RS256 ID-token signing.",
  );

  return {
    issuer,
    authorizationEndpoint:
      readAbsoluteEndpoint(
        raw,
        "authorization_endpoint",
      ),
    tokenEndpoint:
      readAbsoluteEndpoint(
        raw,
        "token_endpoint",
      ),
    userInfoEndpoint:
      readAbsoluteEndpoint(
        raw,
        "userinfo_endpoint",
      ),
    jwksUri:
      readAbsoluteEndpoint(
        raw,
        "jwks_uri",
      ),
    grantTypesSupported,
    responseTypesSupported,
    codeChallengeMethodsSupported,
    idTokenSigningAlgorithmsSupported,
    tokenEndpointAuthMethodsSupported:
      readOptionalStringArray(
        raw,
        "token_endpoint_auth_methods_supported",
      ),
    authorizationResponseIssuerParameterSupported:
      readOptionalBoolean(
        raw,
        "authorization_response_iss_parameter_supported",
      ) ?? false,
  };
}

function readAbsoluteEndpoint(
  value: Readonly<Record<string, unknown>>,
  key: string,
): string {
  const endpoint =
    readRequiredString(value, key);

  let url: URL;

  try {
    url = new URL(endpoint);
  } catch (cause) {
    throw new AquariConfigurationError(
      `Aquari OIDC discovery field '${key}' must be an absolute URL.`,
      { cause },
    );
  }

  if (
    url.protocol !== "https:" &&
    !(
      url.protocol === "http:" &&
      isLocalDevelopmentHost(url.hostname)
    )
  ) {
    throw new AquariConfigurationError(
      `Aquari OIDC discovery field '${key}' must use HTTPS outside local development.`,
    );
  }

  if (
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.hash.length > 0
  ) {
    throw new AquariConfigurationError(
      `Aquari OIDC discovery field '${key}' contains unsupported URL components.`,
    );
  }

  return url.toString();
}

function readRequiredString(
  value: Readonly<Record<string, unknown>>,
  key: string,
): string {
  const item = value[key];

  if (
    typeof item !== "string" ||
    item.length === 0 ||
    item !== item.trim()
  ) {
    throw new AquariConfigurationError(
      `Aquari OIDC discovery field '${key}' must be a non-empty normalized string.`,
    );
  }

  return item;
}

function readRequiredStringArray(
  value: Readonly<Record<string, unknown>>,
  key: string,
): readonly string[] {
  const items =
    readStringArray(value[key]);

  if (
    items === undefined ||
    items.length === 0
  ) {
    throw new AquariConfigurationError(
      `Aquari OIDC discovery field '${key}' must be a non-empty string array.`,
    );
  }

  return items;
}

function readOptionalStringArray(
  value: Readonly<Record<string, unknown>>,
  key: string,
): readonly string[] {
  return readStringArray(value[key]) ?? [];
}

function readStringArray(
  value: unknown,
): readonly string[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }

  const source: readonly unknown[] =
    value;

  const items: string[] = [];

  for (const item of source) {
    if (
      typeof item !== "string" ||
      item.length === 0 ||
      item !== item.trim()
    ) {
      return undefined;
    }

    items.push(item);
  }

  return items;
}

function readOptionalBoolean(
  value: Readonly<Record<string, unknown>>,
  key: string,
): boolean | undefined {
  const item = value[key];

  return typeof item === "boolean"
    ? item
    : undefined;
}

function requireValue(
  values: readonly string[],
  required: string,
  message: string,
): void {
  if (!values.includes(required)) {
    throw new AquariConfigurationError(
      message,
    );
  }
}

function isLocalDevelopmentHost(
  hostname: string,
): boolean {
  const normalized =
    hostname.toLowerCase();

  return (
    normalized === "localhost" ||
    normalized === "127.0.0.1" ||
    normalized === "[::1]" ||
    normalized === "::1"
  );
}

function isRecord(
  value: unknown,
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}
