import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readApiResponse } from './api.js';

test('plain-text query deserialization failures retain the server message', async () => {
  const message = 'Failed to deserialize query string: destination: invalid IP address syntax';
  const result = await readApiResponse(new Response(message, {status:400}));
  assert.deepEqual(result, {error:message});
});

test('API responses preserve JSON, no-content and empty-error behavior', async () => {
  assert.deepEqual(await readApiResponse(new Response('{"rows":[]}')), {rows:[]});
  assert.deepEqual(await readApiResponse(new Response('{"error":"Session expired"}', {status:401})), {error:'Session expired'});
  assert.equal(await readApiResponse(new Response(null, {status:204})), null);
  assert.deepEqual(await readApiResponse(new Response('', {status:503})), {error:'Request failed (503)'});
  await assert.rejects(readApiResponse(new Response('<html>Proxy error</html>')), /invalid JSON response/);
});
