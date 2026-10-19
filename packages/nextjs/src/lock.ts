/**
 * Coordinates refresh-token rotation for one logical application session.
 */
export interface AquariRefreshLock {
  runExclusive<T>(
    key: string,
    operation: () => Promise<T>,
  ): Promise<T>;
}

/**
 * Serializes refresh-sensitive session work inside one JavaScript process.
 *
 * Multi-instance deployments must provide an AquariRefreshLock whose
 * exclusivity is shared by every application instance.
 */
export class InMemoryAquariRefreshLock
  implements AquariRefreshLock {
  readonly #tails =
    new Map<string, Promise<void>>();

  public async runExclusive<T>(
    key: string,
    operation: () => Promise<T>,
  ): Promise<T> {
    if (key.length === 0) {
      throw new TypeError(
        "Aquari refresh lock key must not be empty.",
      );
    }

    const previous =
      this.#tails.get(key) ??
      Promise.resolve();

    let release!: () => void;

    const current =
      new Promise<void>(
        resolve => {
          release = resolve;
        },
      );

    const tail =
      previous.then(
        () => current,
      );

    this.#tails.set(
      key,
      tail,
    );

    await previous;

    try {
      return await operation();
    } finally {
      release();

      if (
        this.#tails.get(key) ===
        tail
      ) {
        this.#tails.delete(key);
      }
    }
  }
}
