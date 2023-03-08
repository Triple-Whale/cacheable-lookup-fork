import { Resolver, promises as dnsPromises, lookup } from "dns";

type AsyncResolver = dnsPromises.Resolver;

export type IPFamily = 4 | 6;
export type EntrySource = "query" | "cache";

type TPromise<T> = T | Promise<T>;

export interface CacheInstance {
	set(
		hostname: string,
		entries: EntryObject[],
		ttl: number
	): TPromise<void | boolean | this>;
	get(hostname: string): TPromise<EntryObject[] | undefined>;
	delete(hostname: string): TPromise<boolean>;
	clear(): TPromise<void>;
}

export interface Options {
	/**
	 * Custom cache instance. If `undefined`, it will create a new one.
	 * @default undefined
	 */
	cache?: CacheInstance;
	/**
	 * Limits the cache time (TTL). If set to `0`, it will make a new DNS query each time.
	 * @default Infinity
	 */
	maxTtl?: number;
	/**
	 * DNS Resolver used to make DNS queries.
	 * @default new dns.promises.Resolver()
	 */
	resolver?: Resolver | AsyncResolver;
	/**
	 * When the DNS server responds with `ENOTFOUND` or `ENODATA` and the OS reports that the entry is available,
	 * it will use `dns.lookup(...)` directly for the requested hostnames for the specified amount of time (in seconds).
	 *
	 * If you don't query internal hostnames (such as `localhost`, `database.local` etc.),
	 * it is strongly recommended to set this value to `0`.
	 * @default 3600
	 */
	fallbackDuration?: number;
	/**
	 * The time how long it needs to remember failed queries (TTL in seconds).
	 *
	 * **Note**: This option is independent, `options.maxTtl` does not affect this.
	 * @default 0.15
	 */
	errorTtl?: number;
	/**
	 * The fallback function to use when the DNS server responds with `ENOTFOUND` or `ENODATA`.
	 *
	 * **Note**: This has no effect if the `fallbackDuration` option is less than `1`.
	 * @default dns.lookup
	 */
	lookup?: typeof lookup | false;
}

export interface EntryObject {
	/**
	 * The IP address (can be an IPv4 or IPv5 address).
	 */
	readonly address: string;
	/**
	 * The IP family.
	 */
	readonly family: IPFamily;
	/**
	 * The original TTL.
	 */
	readonly ttl?: number;
	/**
	 * The expiration timestamp.
	 */
	readonly expires?: number;
	/**
	 * Whether this entry comes from the cache or a query
	 */
	readonly source?: EntrySource;
}

export interface LookupOptions {
	/**
	 * One or more supported getaddrinfo flags. Multiple flags may be passed by bitwise ORing their values.
	 */
	hints?: number;
	/**
	 * The record family. Must be `4` or `6`. IPv4 and IPv6 addresses are both returned by default.
	 */
	family?: IPFamily;
	/**
	 * When `true`, the callback returns all resolved addresses in an array. Otherwise, returns a single address.
	 * @default false
	 */
	all?: boolean;
}
