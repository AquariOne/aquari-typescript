/**
 * Defines opaque server-side storage for Aquari Next.js transaction and session state.
 */
export interface AquariSessionStore {
  /**
   * Reads opaque application session state by key and returns null when the entry is absent
   * or expired.
   */
  get(
    key: string,
  ): Promise<string | null>;

  /**
   * Stores opaque application session state by key with the supplied expiration time.
   */
  set(
    key: string,
    value: string,
    expiresAt: Date,
  ): Promise<void>;

  /**
   * Removes opaque application session state for the supplied key.
   */
  delete(
    key: string,
  ): Promise<void>;
}

interface MemoryEntry {
  value: string;
  expiresAt: number;
}

/**
 * Provides process-local session storage for development and single-process use. Use
 * shared durable storage in multi-instance production deployments.
 */
export class InMemoryAquariSessionStore
  implements AquariSessionStore {
  readonly #entries =
    new Map<string, MemoryEntry>();

  /**
   * Reads opaque application session state by key and returns null when the entry is absent
   * or expired.
   */
  public async get(
    key: string,
  ): Promise<string | null> {
    await Promise.resolve();

    const entry =
      this.#entries.get(key);

    if (entry === undefined) {
      return null;
    }

    if (
      entry.expiresAt <= Date.now()
    ) {
      this.#entries.delete(key);

      return null;
    }

    return entry.value;
  }

  /**
   * Stores opaque application session state by key with the supplied expiration time.
   */
  public async set(
    key: string,
    value: string,
    expiresAt: Date,
  ): Promise<void> {
    await Promise.resolve();

    const timestamp =
      expiresAt.getTime();

    if (
      !Number.isFinite(timestamp) ||
      timestamp <= Date.now()
    ) {
      throw new RangeError(
        "Aquari session store expiresAt must be in the future.",
      );
    }

    this.#entries.set(
      key,
      {
        value,
        expiresAt:
          timestamp,
      },
    );
  }

  /**
   * Removes opaque application session state for the supplied key.
   */
  public async delete(
    key: string,
  ): Promise<void> {
    await Promise.resolve();

    this.#entries.delete(key);
  }
}
