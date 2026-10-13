import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isIP } from 'node:net';
import { drilldown, queryHash, localDate, isIPAddress, addressFilterError } from './query.js';

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

test('address filters accept strict IPv4 and IPv6 syntax', () => {
  const addresses = ['0.0.0.0', '192.0.2.1', '255.255.255.255', '::', '::1', '2001:db8::1', '2001:DB8:0:1:2:3:4:5', '::ffff:192.0.2.1', '1:2:3:4:5:6:192.0.2.1', '', '22', '0x7f.0.0.1', '192.0.2', '192.0.2.256', '192.00.2.1', '192.0.2.1/32', 'example.com', '2001:db8:::1', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', '[::1]', '::ffff:192.0.2.256', '::ffff:192.00.2.1', '::1/path'];
  for (const address of addresses) assert.equal(isIPAddress(address), isIP(address) !== 0, address);
  assert.equal(addressFilterError({source:' 192.0.2.1 ', destination:' 2001:db8::1 '}), '');
  assert.equal(addressFilterError({}), '');
});

test('entering a port in an IP filter points to the corresponding port field', () => {
  assert.equal(addressFilterError({destination:'22'}), 'Destination IP must be an IPv4 or IPv6 address. To filter port 22, use Destination port.');
  assert.match(addressFilterError({source:'443'}), /use Source port \(sample\)/);
  assert.equal(addressFilterError({destination:'65536'}), 'Destination IP must be an IPv4 or IPv6 address.');
  assert.equal(addressFilterError({destination:'192.0.2.1/24'}), 'Destination IP must be an IPv4 or IPv6 address.');
});
