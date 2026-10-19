import {
  AquariTransportError,
} from "./errors.js";

export type AquariWireRecord =
  Readonly<Record<string, unknown>>;

export function asRecord(
  value: unknown,
  label: string,
): AquariWireRecord {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value)
  ) {
    throw malformed(label);
  }

  return value as AquariWireRecord;
}

export function asString(
  value: unknown,
  label: string,
): string {
  if (typeof value !== "string") {
    throw malformed(label);
  }

  return value;
}

export function asNonEmptyString(
  value: unknown,
  label: string,
): string {
  const result = asString(value, label);

  if (result.length === 0) {
    throw malformed(label);
  }

  return result;
}

export function asOptionalString(
  value: unknown,
  label: string,
): string | undefined {
  if (
    value === undefined ||
    value === null
  ) {
    return undefined;
  }

  return asString(value, label);
}

export function asBoolean(
  value: unknown,
  label: string,
): boolean {
  if (typeof value !== "boolean") {
    throw malformed(label);
  }

  return value;
}

export function asNumber(
  value: unknown,
  label: string,
): number {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value)
  ) {
    throw malformed(label);
  }

  return value;
}

export function asInteger(
  value: unknown,
  label: string,
): number {
  const result = asNumber(
    value,
    label,
  );

  if (!Number.isInteger(result)) {
    throw malformed(label);
  }

  return result;
}

export function asArray(
  value: unknown,
  label: string,
): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw malformed(label);
  }

  const result: readonly unknown[] =
    value;

  return result;
}

export function asStringArray(
  value: unknown,
  label: string,
): readonly string[] {
  const source =
    asArray(value, label);

  const result: string[] = [];

  for (const item of source) {
    result.push(
      asString(item, label),
    );
  }

  return Object.freeze(result);
}

export function asOptionalRecord(
  value: unknown,
  label: string,
): AquariWireRecord | undefined {
  if (
    value === undefined ||
    value === null
  ) {
    return undefined;
  }

  return asRecord(value, label);
}

export function asIsoDateString(
  value: unknown,
  label: string,
): string {
  const result =
    asNonEmptyString(
      value,
      label,
    );

  if (
    Number.isNaN(
      Date.parse(result),
    )
  ) {
    throw malformed(label);
  }

  return result;
}

export function asOptionalIsoDateString(
  value: unknown,
  label: string,
): string | undefined {
  if (
    value === undefined ||
    value === null
  ) {
    return undefined;
  }

  return asIsoDateString(
    value,
    label,
  );
}

export function malformed(
  label: string,
): AquariTransportError {
  return new AquariTransportError(
    `Aquari returned a malformed ${label}.`,
  );
}
