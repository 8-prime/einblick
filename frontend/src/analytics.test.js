import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rankingRows, liveCountries } from './analytics.js';

test('rankings switch metrics and preserve tail and unavailable traffic', () => {
  const rows = [
    {key: 'US', label: 'United States', packets: 70, bytes: 100},
    {key: 'DE', label: 'Germany', packets: 10, bytes: 700},
    {key: 'unknown', label: 'Country unavailable', packets: 10, bytes: 100},
    {key: 'untracked', label: 'Other / untracked', packets: 10, bytes: 100},
  ];
  assert.equal(rankingRows(rows, 'packets', 1)[0].key, 'US');
  assert.equal(rankingRows(rows, 'bytes', 1)[0].key, 'DE');
  for (const metric of ['packets', 'bytes']) {
    const ranked = rankingRows(rows, metric, 1);
    assert.equal(ranked.reduce((sum, row) => sum + row[metric], 0), metric === 'packets' ? 100 : 1000);
    assert.deepEqual(ranked.slice(-2).map(row => row.key), ['unknown', 'untracked']);
  }
});

test('live country shares use process totals and account for missing sources', () => {
  const result = liveCountries({totals: {packets: 9999, bytes: 99999}, session_totals: {packets: 100, bytes: 1000}, sources: [
    {packets: 60, bytes: 600, ip_info: {country_code: 'DE', country: 'Germany'}},
    {packets: 20, bytes: 300, ip_info: {asn: 123}},
  ]});
  assert.equal(result.totals.packets, 100);
  assert.equal(result.mappedPackets, 60);
  assert.equal(result.rows.find(row => row.key === 'unknown').packets, 20);
  assert.equal(result.rows.find(row => row.key === 'untracked').bytes, 100);
  assert.equal(result.rows.reduce((sum, row) => sum + row.packets, 0), 100);
  assert.deepEqual(rankingRows(liveCountries(null).rows, 'packets'), []);
});
