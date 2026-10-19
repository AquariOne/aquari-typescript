export {
  AquariAuthClient,
  type AquariAuthorizationPrompt,
  type AquariAuthorizationTransaction,
  type AquariAuthClientConfiguration,
  type AquariBeginAuthorizationOptions,
  type AquariBeginAuthorizationResult,
  type AquariCompleteAuthorizationOptions,
  type AquariCompleteAuthorizationResult,
  type AquariDiscoverOptions,
  type AquariRefreshOptions,
  type AquariUserInfoOptions,
} from "./auth.js";

export {
  AquariClient,
  type AquariClientOptions,
} from "./client.js";

export {
  DEFAULT_MAX_RETRIES,
  DEFAULT_MAX_RETRY_DELAY_MS,
  DEFAULT_REQUEST_TIMEOUT_MS,
  normalizeAquariBaseUrl,
  resolveAquariTransportConfiguration,
  type AquariTransportConfiguration,
  type ResolvedAquariTransportConfiguration,
} from "./config.js";

export {
  AquariApiError,
  AquariAuthenticationError,
  AquariAuthorizationError,
  AquariConfigurationError,
  AquariConflictError,
  AquariError,
  AquariNotFoundError,
  AquariOAuthError,
  AquariQuotaError,
  AquariRateLimitError,
  AquariTimeoutError,
  AquariTransportError,
  AquariValidationError,
  classifyAquariApiError,
  type AquariApiErrorOptions,
  type AquariErrorDetails,
  type AquariOAuthErrorOptions,
  type AquariRateLimitErrorOptions,
  type AquariTransportErrorOptions,
} from "./errors.js";

export {
  type AquariDiscoveryOptions,
  type AquariOidcDiscovery,
} from "./oidc.js";

export {
  type AquariIdentity,
  type AquariTokenSet,
} from "./oauth.js";

export {
  AquariHttpTransport,
  parseRetryAfterMs,
  type AquariHttpMethod,
  type AquariRequestOptions,
  type AquariRetryMode,
} from "./transport.js";


export {
  AquariPassportClient,
  AquariPassportSignalsClient,
  type AquariAuthenticatedRequestOptions,
  type AquariPassport,
  type AquariPassportProfile,
  type AquariPassportSignal,
  type AquariPassportSignalFamily,
  type AquariPassportSignalGetOptions,
  type AquariPassportSignalIssuer,
  type AquariPassportSignalPage,
  type AquariPassportSignalScope,
  type AquariPassportSignalsListOptions,
  type AquariPublicPassport,
  type AquariPublicPassportOptions,
  type AquariPublicPassportSignal,
  type AquariPublicPassportSignalScope,
} from "./passport.js";

export {
  AquariScopes,
  type AquariScope,
} from "./scopes.js";

export {
  AquariTrustClient,
  type AquariTrustAuthority,
  type AquariTrustEvaluation,
  type AquariTrustOutcome,
  type AquariTrustOutcomeType,
  type AquariTrustScope,
  type AquariTrustSignal,
  type AquariTrustSupport,
} from "./trust.js";
