import type {
  AquariHttpTransport,
} from "./transport.js";

import {
  asArray,
  asInteger,
  asIsoDateString,
  asNonEmptyString,
  asOptionalIsoDateString,
  asOptionalRecord,
  asOptionalString,
  asRecord,
} from "./wire.js";

import type {
  AquariAuthenticatedRequestOptions,
} from "./passport.js";

/**
 * Identifies the supported trust outcome category.
 */
export type AquariTrustOutcomeType =
  string;

/**
 * Contains the trust outcomes Aquari calculated for one subject and consumer application.
 */
export interface AquariTrustEvaluation {
  evaluationId: string;
  subjectId: string;
  consumerApplicationId: string;
  evaluatedAt: string;
  outcomes: readonly AquariTrustOutcome[];
}

/**
 * Represents one trust outcome and the signals that support it.
 */
export interface AquariTrustOutcome {
  type: AquariTrustOutcomeType;
  value: string;
  supports: readonly AquariTrustSupport[];
}

/**
 * Explains which trusted mapping and signal support a trust outcome.
 */
export interface AquariTrustSupport {
  mappingId: string;
  mappingVersion: number;
  trustedIssuerId: string;
  signal: AquariTrustSignal;
}

/**
 * Describes the Passport signal that supported a trust outcome.
 */
export interface AquariTrustSignal {
  id: string;
  signalFamily: string;
  definitionId?: string;
  authority: AquariTrustAuthority;
  scope?: AquariTrustScope;
  issuedAt: string;
  expiresAt?: string;
}

/**
 * Identifies the authority attached to a trusted signal.
 */
export interface AquariTrustAuthority {
  type: string;
  id: string;
}

/**
 * Identifies the resource scope attached to a trusted signal.
 */
export interface AquariTrustScope {
  type: string;
  id: string;
}

/**
 * Evaluates the current application's configured trust mappings for an authenticated
 * Aquari subject.
 */
export class AquariTrustClient {
  readonly #transport:
    AquariHttpTransport;

  /**
   * Creates a trust client that uses the supplied Aquari HTTP transport.
   */
  public constructor(
    transport: AquariHttpTransport,
  ) {
    this.#transport = transport;
  }

  /**
   * Requests Aquari trust evaluation for the authenticated subject represented by the
   * supplied access token.
   */
  public async evaluate(
    options: AquariAuthenticatedRequestOptions,
  ): Promise<AquariTrustEvaluation> {
    const value =
      await this.#transport.request<unknown>({
        path:
          "/api/v1/passport/trust/evaluation",
        method: "GET",
        headers: {
          authorization:
            `Bearer ${validateAccessToken(
              options.accessToken,
            )}`,
        },
        ...(options.signal !== undefined
          ? { signal: options.signal }
          : {}),
      });

    return parseTrustEvaluation(
      value,
    );
  }
}

function validateAccessToken(
  value: string,
): string {
  if (
    value.length === 0 ||
    value !== value.trim()
  ) {
    throw new TypeError(
      "Aquari accessToken must be a non-empty value without surrounding whitespace.",
    );
  }

  return value;
}

function parseTrustEvaluation(
  value: unknown,
): AquariTrustEvaluation {
  const record =
    asRecord(
      value,
      "trust evaluation",
    );

  const source =
    asArray(
      record["outcomes"],
      "trust evaluation outcomes",
    );

  const outcomes:
    AquariTrustOutcome[] = [];

  for (const item of source) {
    outcomes.push(
      parseOutcome(item),
    );
  }

  return {
    evaluationId:
      asNonEmptyString(
        record["evaluationId"],
        "trust evaluation id",
      ),
    subjectId:
      asNonEmptyString(
        record["subjectId"],
        "trust subject id",
      ),
    consumerApplicationId:
      asNonEmptyString(
        record["consumerApplicationId"],
        "trust consumer application id",
      ),
    evaluatedAt:
      asIsoDateString(
        record["evaluatedAt"],
        "trust evaluatedAt",
      ),
    outcomes:
      Object.freeze(outcomes),
  };
}

function parseOutcome(
  value: unknown,
): AquariTrustOutcome {
  const record =
    asRecord(
      value,
      "trust outcome",
    );

  const source =
    asArray(
      record["supports"],
      "trust outcome supports",
    );

  const supports:
    AquariTrustSupport[] = [];

  for (const item of source) {
    supports.push(
      parseSupport(item),
    );
  }

  return {
    type:
      asNonEmptyString(
        record["type"],
        "trust outcome type",
      ),
    value:
      asNonEmptyString(
        record["value"],
        "trust outcome value",
      ),
    supports:
      Object.freeze(supports),
  };
}

function parseSupport(
  value: unknown,
): AquariTrustSupport {
  const record =
    asRecord(
      value,
      "trust support",
    );

  return {
    mappingId:
      asNonEmptyString(
        record["mappingId"],
        "trust mapping id",
      ),
    mappingVersion:
      asInteger(
        record["mappingVersion"],
        "trust mapping version",
      ),
    trustedIssuerId:
      asNonEmptyString(
        record["trustedIssuerId"],
        "trusted issuer id",
      ),
    signal:
      parseTrustSignal(
        record["signal"],
      ),
  };
}

function parseTrustSignal(
  value: unknown,
): AquariTrustSignal {
  const record =
    asRecord(
      value,
      "trust signal",
    );

  const authority =
    asRecord(
      record["authority"],
      "trust authority",
    );

  const scope =
    asOptionalRecord(
      record["scope"],
      "trust signal scope",
    );

  return {
    id:
      asNonEmptyString(
        record["id"],
        "trust signal id",
      ),
    signalFamily:
      asNonEmptyString(
        record["signalFamily"],
        "trust signal family",
      ),
    ...optionalProperty(
      "definitionId",
      asOptionalString(
        record["definitionId"],
        "trust signal definition id",
      ),
    ),
    authority: {
      type:
        asNonEmptyString(
          authority["type"],
          "trust authority type",
        ),
      id:
        asNonEmptyString(
          authority["id"],
          "trust authority id",
        ),
    },
    ...(scope !== undefined
      ? {
          scope: {
            type:
              asNonEmptyString(
                scope["type"],
                "trust scope type",
              ),
            id:
              asNonEmptyString(
                scope["id"],
                "trust scope id",
              ),
          },
        }
      : {}),
    issuedAt:
      asIsoDateString(
        record["issuedAt"],
        "trust signal issuedAt",
      ),
    ...optionalProperty(
      "expiresAt",
      asOptionalIsoDateString(
        record["expiresAt"],
        "trust signal expiresAt",
      ),
    ),
  };
}

function optionalProperty<
  TKey extends string,
  TValue,
>(
  key: TKey,
  value: TValue | undefined,
): Partial<Record<TKey, TValue>> {
  return value === undefined
    ? {}
    : {
        [key]: value,
      } as Record<TKey, TValue>;
}
