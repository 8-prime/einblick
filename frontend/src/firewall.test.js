import { test } from 'node:test';
import assert from 'node:assert/strict';
import { networkContains, matchingRules, ruleIsActive, ruleStatus } from './firewall.js';

test('source rules include IPv4 host and covering subnet bans', () => {
  assert.equal(networkContains('192.0.2.10/32', '192.0.2.10'), true);
  assert.equal(networkContains('192.0.2.10/32', '192.0.2.11'), false);
  assert.equal(networkContains('192.0.2.0/24', '192.0.2.255'), true);
  assert.equal(networkContains('192.0.2.0/24', '192.0.3.0'), false);
  assert.equal(networkContains('192.0.2.128/25', '192.0.2.127'), false);
  assert.equal(networkContains('192.0.2.128/25', '192.0.2.128'), true);
  assert.equal(networkContains('0.0.0.0/0', '203.0.113.1'), true);
});

test('IPv6 prefix matching handles equivalent spelling, partial groups and mapped IPv4', () => {
  assert.equal(networkContains('2001:db8::1/128', '2001:0DB8:0:0:0:0:0:1'), true);
  assert.equal(networkContains('2001:db8::1/128', '2001:db8::2'), false);
  assert.equal(networkContains('2001:db8::/32', '2001:db8:ffff::1'), true);
  assert.equal(networkContains('2001:db8::/32', '2001:db9::1'), false);
  assert.equal(networkContains('2001:db8:0:0:8000::/65', '2001:db8::7fff:ffff:ffff:ffff'), false);
  assert.equal(networkContains('2001:db8:0:0:8000::/65', '2001:db8::8000:0:0:0'), true);
  assert.equal(networkContains('::/0', '2001:db8::1'), true);
  assert.equal(networkContains('::ffff:c000:201/128', '::ffff:192.0.2.1'), true);
  assert.equal(networkContains('192.0.2.0/24', '::ffff:192.0.2.1'), false);
  assert.equal(networkContains('::/0', '192.0.2.1'), false);
});

test('invalid addresses and prefixes do not match any rules', () => {
  for (const network of ['192.0.2.0/33', '2001:db8::/129', '192.0.2.0/-1', '192.0.2.0/', '192.0.2.0/24/32', 'invalid/24']) assert.equal(networkContains(network, '192.0.2.1'), false, network);
  assert.equal(networkContains('0.0.0.0/0', '22'), false);
  assert.equal(networkContains('::/0', '2001:db8:::1'), false);
});

test('only enabled, unexpired block rules prevent a duplicate source ban', () => {
  const rules = [
    {id:1, network:'192.0.2.0/24', kind:'block', enabled:true, expires:1100},
    {id:2, network:'192.0.2.10/32', kind:'block', enabled:true, expires:1000},
    {id:3, network:'192.0.2.10/32', kind:'block', enabled:false, expires:null},
    {id:4, network:'192.0.2.10/32', kind:'allow', enabled:true, expires:null},
    {id:5, network:'203.0.113.0/24', kind:'block', enabled:true, expires:null},
  ];
  const matches = matchingRules(rules, '192.0.2.10');
  assert.deepEqual(matches.map(rule => rule.id), [1,2,3,4]);
  assert.deepEqual(matches.filter(rule => rule.kind === 'block' && ruleIsActive(rule, 1000)).map(rule => rule.id), [1]);
  assert.equal(matches.some(rule => rule.kind === 'block' && ruleIsActive(rule, 1100)), false);
  assert.equal(ruleIsActive({...rules[0], expires:null, applied:false, error:'Update failed'}, 1000), true);
});

test('rule status distinguishes failed, pending, removed and expired bans', () => {
  const rule = {enabled:true, expires:null, applied:true, error:null};
  assert.equal(ruleStatus(rule, 1000), 'Applied');
  assert.equal(ruleStatus({...rule, applied:false}, 1000), 'Inactive / pending');
  assert.equal(ruleStatus({...rule, error:'Update failed'}, 1000), 'Failed');
  assert.equal(ruleStatus({...rule, enabled:false, error:'Old failure'}, 1000), 'Removed');
  assert.equal(ruleStatus({...rule, expires:1000, error:'Old failure'}, 1000), 'Expired');
});
