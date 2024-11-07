import dns from "node:dns";
import { promisify } from "node:util";
import os from "node:os";
import { LookupOptions } from "./types";

const kExpires = Symbol("expires");

const supportsALL = typeof dns.ALL === "number";

function map4to6(entries) {
  for (const entry of entries) {
    if (entry.family === 6) {
      continue;
    }
    entry.address = `::ffff:${entry.address}`;
    entry.family = 6;
  }
}

function getIfaceInfo(): { has4: boolean; has6: boolean } {
  let has4 = false;
  let has6 = false;

  for (const device of Object.values(os.networkInterfaces())) {
    if (!device) continue;
    for (const iface of device) {
      if (iface.internal) {
        continue;
      }

      if (iface.family === "IPv6") {
        has6 = true;
      } else {
        has4 = true;
      }

      if (has4 && has6) {
        return { has4, has6 };
      }
    }
  }

  if (!has4 && !has6) {
    has4 = true;
  }

  return { has4, has6 };
}

function isIterable(map): boolean {
  return Symbol.iterator in map;
}

function ignoreNoResultErrors<T = any>(dnsPromise: Promise<T>): Promise<T> {
  // @ts-ignore
  return dnsPromise.catch((error) => {
    if (
      error.code === "ENODATA" ||
      error.code === "ENOTFOUND" ||
      error.code === "ENOENT" // Windows: name exists, but not this record type
    ) {
      return [];
    }
    throw error;
  });
}

const ttl = { ttl: true };
const all = { all: true };
const all4 = { all: true, family: 4 };
const all6 = { all: true, family: 6 };

export default class CacheableLookup {
  maxTtl;
  errorTtl;
  _cache;
  _dnsLookup = promisify(dns.lookup);
  resolver = new dns.promises.Resolver();
  stats;
  _iface;
  _pending;
  _nextRemovalTime;
  _hostnamesToFallback;
  fallbackDuration;
  _fallbackInterval;
  _removalTimeout;
  constructor({
    cache = new Map(),
    maxTtl = Infinity,
    fallbackDuration = 3600,
    errorTtl = 0.15,
  } = {}) {
    this.maxTtl = maxTtl;
    this.errorTtl = errorTtl;
    this._cache = cache;
    this.stats = {
      cache: 0,
      query: 0,
    };

    this._iface = getIfaceInfo();

    this._pending = {};
    this._nextRemovalTime = false;
    this._hostnamesToFallback = new Set();

    this.fallbackDuration = fallbackDuration;

    if (fallbackDuration > 0) {
      const interval = setInterval(() => {
        this._hostnamesToFallback.clear();
      }, fallbackDuration * 1000);

      /* istanbul ignore next: There is no `interval.unref()` when running inside an Electron renderer */
      if (interval.unref) {
        interval.unref();
      }

      this._fallbackInterval = interval;
    }

    this.lookup = this.lookup.bind(this);
    this.lookupAsync = this.lookupAsync.bind(this);
  }

  set servers(servers) {
    this.clear();

    this.resolver.setServers(servers);
  }

  get servers() {
    return this.resolver.getServers();
  }

  lookup(hostname, options, callback?) {
    if (typeof options === "function") {
      callback = options;
      options = {};
    } else if (typeof options === "number") {
      options = {
        family: options,
      };
    }

    if (!callback) {
      throw new Error("Callback must be a function.");
    }

    this.lookupAsync(hostname, options).then((result) => {
      if (options.all) {
        callback(null, result);
      } else {
        callback(
          null,
          result.address,
          result.family,
          result.expires,
          result.ttl,
          result.source
        );
      }
    }, callback);
  }

  async lookupAsync(hostname, options: LookupOptions = {}) {
    let results = await this.query(hostname);

    if (options.family === 6) {
      const filtered = results.filter((entry) => entry.family === 6);

      if (options.hints & dns.V4MAPPED) {
        if ((supportsALL && options.hints & dns.ALL) || filtered.length === 0) {
          map4to6(results);
        } else {
          results = filtered;
        }
      } else {
        results = filtered;
      }
    } else if (options.family === 4) {
      results = results.filter((entry) => entry.family === 4);
    }

    if (options.hints & dns.ADDRCONFIG) {
      results = results.filter((entry) =>
        entry.family === 6 ? this._iface.has6 : this._iface.has4
      );
    }

    if (results.length === 0) {
      const error: any = new Error(`cacheableLookup ENOTFOUND ${hostname}`);
      error.code = "ENOTFOUND";
      error.hostname = hostname;
      throw error;
    }

    if (options.all) {
      return results;
    }

    return results[0];
  }

  async query(hostname) {
    let source = "cache";
    let result = await this._cache.get(hostname);

    if (result) {
      this.stats.cache++;
    }

    if (!result) {
      const pending = this._pending[hostname];
      if (pending) {
        this.stats.cache++;
        result = await pending;
      } else {
        source = "query";
        this._pending[hostname] = this.queryAndCache(hostname);
        const newPromise = this._pending[hostname];
        this.stats.query++;
        try {
          result = await newPromise;
        } finally {
          delete this._pending[hostname];
        }
      }
    }

    result = result.map((entry) => {
      return { ...entry, source };
    });

    return result;
  }

  async _resolve(hostname) {
    if (hostname && !hostname.endsWith(".")) {
      hostname += ".";
    }
    // ANY is unsafe as it doesn't trigger new queries in the underlying server.
    const [A, AAAA] = await Promise.all([
      ignoreNoResultErrors(this.resolver.resolve4(hostname, ttl)),
      ignoreNoResultErrors(this.resolver.resolve6(hostname, ttl)),
    ])

    let aTtl = 0;
    let aaaaTtl = 0;
    let cacheTtl = 0;

    const now = Date.now();

    for (const entry of A) {
      // @ts-ignore
      entry.family = 4;
      // @ts-ignore
      entry.expires = now + entry.ttl * 1000;
      // @ts-ignore
      aTtl = Math.max(aTtl, entry.ttl);
    }

    for (const entry of AAAA) {
      // @ts-ignore
      entry.family = 6;
      // @ts-ignore
      entry.expires = now + entry.ttl * 1000;
      // @ts-ignore
      aaaaTtl = Math.max(aaaaTtl, entry.ttl);
    }

    if (A.length > 0) {
      if (AAAA.length > 0) {
        cacheTtl = Math.min(aTtl, aaaaTtl);
      } else {
        cacheTtl = aTtl;
      }
    } else {
      cacheTtl = aaaaTtl;
    }

    if (hostname.endsWith('svc.cluster.local.')) {
      cacheTtl = 3600;
    }

    return {
      entries: [...A, ...AAAA],
      cacheTtl,
    };
  }

  async _lookup(hostname) {
    try {
      const [A, AAAA] = await Promise.all([
        // Passing {all: true} doesn't return all IPv4 and IPv6 entries.
        // See https://github.com/szmarczak/cacheable-lookup/issues/42
        ignoreNoResultErrors(this._dnsLookup(hostname, all4)),
        ignoreNoResultErrors(this._dnsLookup(hostname, all6)),
      ]) as dns.LookupAddress[][];

      return {
        entries: [...A, ...AAAA],
        cacheTtl: 0,
      };
    } catch {
      return {
        entries: [],
        cacheTtl: 0,
      };
    }
  }

  async _set(hostname, data, cacheTtl) {
    if (this.maxTtl > 0 && cacheTtl > 0) {
      cacheTtl = Math.min(cacheTtl, this.maxTtl) * 1000;
      data[kExpires] = Date.now() + cacheTtl;

      try {
        await this._cache.set(hostname, data, cacheTtl);
      } catch (error) {
        this.lookupAsync = async () => {
          const cacheError: any = new Error(
            "Cache Error. Please recreate the CacheableLookup instance."
          );
          cacheError.cause = error;

          throw cacheError;
        };
      }

      if (isIterable(this._cache)) {
        this._tick(cacheTtl);
      }
    }
  }

  async queryAndCache(hostname) {
    if (this._hostnamesToFallback.has(hostname)) {
      return this._dnsLookup(hostname, all);
    }

    let query = await this._resolve(hostname);

    if (query.entries.length === 0 && this._dnsLookup) {
      // @ts-ignore
      query = await this._lookup(hostname);

      if (query.entries.length !== 0 && this.fallbackDuration > 0) {
        // Use `dns.lookup(...)` for that particular hostname
        this._hostnamesToFallback.add(hostname);
      }
    }

    const cacheTtl =
      query.entries.length === 0 ? this.errorTtl : query.cacheTtl;
    await this._set(hostname, query.entries, cacheTtl);

    return query.entries;
  }

  _tick(ms) {
    const nextRemovalTime = this._nextRemovalTime;

    if (!nextRemovalTime || ms < nextRemovalTime) {
      clearTimeout(this._removalTimeout);

      this._nextRemovalTime = ms;

      this._removalTimeout = setTimeout(() => {
        this._nextRemovalTime = false;

        let nextExpiry = Infinity;

        const now = Date.now();

        for (const [hostname, entries] of this._cache) {
          const expires = entries[kExpires];

          if (now >= expires) {
            this._cache.delete(hostname);
          } else if (expires < nextExpiry) {
            nextExpiry = expires;
          }
        }

        if (nextExpiry !== Infinity) {
          this._tick(nextExpiry - now);
        }
      }, ms);

      /* istanbul ignore next: There is no `timeout.unref()` when running inside an Electron renderer */
      if (this._removalTimeout.unref) {
        this._removalTimeout.unref();
      }
    }
  }

  updateInterfaceInfo() {
    const { _iface } = this;

    this._iface = getIfaceInfo();

    if (
      (_iface.has4 && !this._iface.has4) ||
      (_iface.has6 && !this._iface.has6)
    ) {
      this._cache.clear();
    }
  }

  clear(hostname?) {
    if (hostname) {
      this._cache.delete(hostname);
      return;
    }

    this._cache.clear();
  }
}
