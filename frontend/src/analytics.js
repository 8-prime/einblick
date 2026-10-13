export const formatNumber = (n = 0) => new Intl.NumberFormat('en', { notation: n >= 1000000 ? 'compact' : 'standard', maximumFractionDigits: 1 }).format(n);
export const formatBytes = (n = 0) => n >= 1e9 ? `${(n / 1e9).toFixed(2)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : n >= 1000 ? `${(n / 1000).toFixed(1)} kB` : `${n} B`;
export const percentage = (n, total) => total > 0 ? `${(100 * n / total).toFixed(1)}%` : '0%';

// Preserve unknown/untracked groups when limiting a ranking. All displayed
// shares use the aggregate total, including traffic outside retained sources.
export function rankingRows(rows, metric, limit = 8) {
  const special = new Set(['unknown', 'untracked', 'other', 'none']);
  const known = rows.filter(row => !special.has(row.key)).sort((a, b) => b[metric] - a[metric] || a.key.localeCompare(b.key));
  const tail = [...known.slice(limit), ...rows.filter(row => row.key === 'other')];
  const other = tail.reduce((sum, row) => ({key: 'other', label: 'Other tracked groups', packets: sum.packets + row.packets, bytes: sum.bytes + row.bytes}), {key: 'other', label: 'Other tracked groups', packets: 0, bytes: 0});
  return [...known.slice(0, limit), ...(other[metric] > 0 ? [other] : []), ...rows.filter(row => special.has(row.key) && row.key !== 'other')].filter(row => row[metric] > 0);
}

export function liveCountries(snapshot) {
  const totals = snapshot?.session_totals || {packets: 0, bytes: 0};
  const groups = new Map();
  let trackedPackets = 0, trackedBytes = 0, mappedPackets = 0;
  for (const source of snapshot?.sources || []) {
    const key = source.ip_info?.country_code || 'unknown';
    const group = groups.get(key) || {key, label: source.ip_info?.country || source.ip_info?.country_code || 'Country unavailable', packets: 0, bytes: 0};
    group.packets += source.packets; group.bytes += source.bytes;
    trackedPackets += source.packets; trackedBytes += source.bytes;
    if (key !== 'unknown') mappedPackets += source.packets;
    groups.set(key, group);
  }
  groups.set('untracked', {key: 'untracked', label: 'Other / untracked sources', packets: Math.max(0, totals.packets - trackedPackets), bytes: Math.max(0, totals.bytes - trackedBytes)});
  return {rows: [...groups.values()], totals, mappedPackets};
}
