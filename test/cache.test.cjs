const assert = require('node:assert/strict');
const { test } = require('node:test');
const CacheableLookup = require('../module').default;

const hostname = 'bw-internal.pixel-ns.svc.cluster.local';

function setup(t, options = {}) {
  let now = 1000;
  let answers = [{ address: '10.0.0.1', ttl: 30 }];
  t.mock.method(performance, 'now', () => now);
  const lookup = new CacheableLookup({ fallbackDuration: 0, ...options });
  // Advancing the clock must test expiry without running cleanup timers.
  lookup._cache.ttlResolution = 0;
  const resolve4 = t.mock.method(lookup.resolver, 'resolve4', async () =>
    answers.map((entry) => ({ ...entry })),
  );
  const resolve6 = t.mock.method(lookup.resolver, 'resolve6', async () => {
    const error = new Error('No IPv6 record');
    error.code = 'ENODATA';
    throw error;
  });
  const osLookup = t.mock.method(lookup, '_dnsLookup', async () => []);

  return {
    lookup,
    resolve4,
    resolve6,
    osLookup,
    advance(ms) {
      now += ms;
    },
    setAnswers(value) {
      answers = value;
    },
  };
}

test('default construction accepts the unlimited TTL cap', (t) => {
  t.mock.method(globalThis, 'setInterval', () => ({ unref() {} }));
  assert.doesNotThrow(() => new CacheableLookup());
});

for (const name of [hostname, `${hostname}.`]) {
  test(`cluster-local DNS expiry refreshes the IP for ${name}`, async (t) => {
    const fixture = setup(t);
    assert.equal((await fixture.lookup.lookupAsync(name)).address, '10.0.0.1');
    fixture.setAnswers([{ address: '10.0.0.2', ttl: 30 }]);
    fixture.advance(29_999);
    assert.equal((await fixture.lookup.lookupAsync(name)).address, '10.0.0.1');
    fixture.advance(2);
    assert.equal((await fixture.lookup.lookupAsync(name)).address, '10.0.0.2');
    assert.equal(fixture.resolve4.mock.callCount(), 2);
    assert.equal(fixture.resolve4.mock.calls[0].arguments[0], `${hostname}.`);
    assert.equal(fixture.osLookup.mock.callCount(), 0);
  });
}

for (const ttl of [0, -1, NaN, Infinity]) {
  test(`DNS TTL ${ttl} cannot create a permanent cache entry`, async (t) => {
    const fixture = setup(t);
    fixture.setAnswers([{ address: '10.0.0.1', ttl }]);
    await fixture.lookup.lookupAsync(hostname);
    fixture.setAnswers([{ address: '10.0.0.2', ttl }]);
    assert.equal((await fixture.lookup.lookupAsync(hostname)).address, '10.0.0.2');
    assert.equal(fixture.resolve4.mock.callCount(), 2);
  });
}

test('maxTtl zero disables caching', async (t) => {
  const fixture = setup(t, { maxTtl: 0 });
  await fixture.lookup.lookupAsync(hostname);
  await fixture.lookup.lookupAsync(hostname);
  assert.equal(fixture.resolve4.mock.callCount(), 2);
});

for (const { ttl, maxTtl } of [{ ttl: 30, maxTtl: 5 }, { ttl: 5, maxTtl: 30 }]) {
  test(`maxTtl ${maxTtl} only shortens DNS TTL ${ttl}`, async (t) => {
    const fixture = setup(t, { maxTtl });
    fixture.setAnswers([{ address: '10.0.0.1', ttl }]);
    await fixture.lookup.lookupAsync(hostname);
    fixture.advance(4999);
    await fixture.lookup.lookupAsync(hostname);
    assert.equal(fixture.resolve4.mock.callCount(), 1);
    fixture.advance(2);
    await fixture.lookup.lookupAsync(hostname);
    assert.equal(fixture.resolve4.mock.callCount(), 2);
  });
}

test('a cached address bundle expires at its earliest DNS TTL', async (t) => {
  const fixture = setup(t);
  fixture.setAnswers([
    { address: '10.0.0.1', ttl: 5 },
    { address: '10.0.0.2', ttl: 30 },
  ]);
  await fixture.lookup.lookupAsync(hostname);
  fixture.setAnswers([{ address: '10.0.0.3', ttl: 30 }]);
  fixture.advance(5001);
  assert.equal((await fixture.lookup.lookupAsync(hostname)).address, '10.0.0.3');
});

test('concurrent refreshes share one A and one AAAA lookup', async (t) => {
  const fixture = setup(t);
  await fixture.lookup.lookupAsync(hostname);
  fixture.advance(30_001);
  await Promise.all(Array.from({ length: 20 }, () => fixture.lookup.lookupAsync(hostname)));
  assert.equal(fixture.resolve4.mock.callCount(), 2);
  assert.equal(fixture.resolve6.mock.callCount(), 2);
  assert.equal(fixture.osLookup.mock.callCount(), 0);
});

test('negative answers use errorTtl in seconds', async (t) => {
  const fixture = setup(t);
  fixture.setAnswers([]);
  await assert.rejects(fixture.lookup.lookupAsync(hostname), { code: 'ENOTFOUND' });
  fixture.advance(100);
  await assert.rejects(fixture.lookup.lookupAsync(hostname), { code: 'ENOTFOUND' });
  assert.equal(fixture.resolve4.mock.callCount(), 1);
  fixture.advance(51);
  await assert.rejects(fixture.lookup.lookupAsync(hostname), { code: 'ENOTFOUND' });
  assert.equal(fixture.resolve4.mock.callCount(), 2);
});
