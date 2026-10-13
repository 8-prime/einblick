import { test } from 'node:test';
import assert from 'node:assert/strict';
import { drilldown, queryHash, localDate } from './query.js';

test('dashboard drilldowns decode transport ports and preserve explicit unknown country', () => {
  assert.deepEqual(drilldown('country', 'CN'), {country:'CN'});
  assert.deepEqual(drilldown('country', 'unknown'), {country:'unknown'});
  assert.deepEqual(drilldown('network', '4134'), {asn:'4134'});
  assert.deepEqual(drilldown('protocol', '6'), {protocol:'6'});
  assert.deepEqual(drilldown('port', '443'), {protocol:'6',port:'443'});
  assert.deepEqual(drilldown('port', '65979'), {protocol:'17',port:'443'});
  for (const key of ['other','untracked','none']) assert.equal(drilldown('port', key), null);
  assert.equal(drilldown('network', 'unknown'), null);
});

test('query URLs roundtrip IPv6, zero ports, ISP names and time boundaries', () => {
  const filters = {source:'2001:db8::1',port:0,organization:'China Telecom & network',country:'CN',from:0,to:3600,interface:'',protocol:null};
  const params = Object.fromEntries(new URLSearchParams(queryHash(filters).split('?')[1]));
  assert.deepEqual(params, {source:filters.source,port:'0',organization:filters.organization,country:'CN',from:'0',to:'3600'});
  const at = 1770000000;
  assert.equal(new Date(localDate(at)).getTime() / 1000, at);
});
