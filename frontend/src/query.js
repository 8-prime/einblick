export function drilldown(kind, key) {
  if (['other', 'untracked', 'none'].includes(key)) return null;
  if (kind === 'country') return {country: key};
  if (key === 'unknown') return null;
  if (kind === 'network') return {asn: key};
  if (kind === 'protocol') return {protocol: key};
  if (kind === 'port') return {protocol: Number(key) >= 65536 ? '17' : '6', port: String(Number(key) % 65536)};
  return null;
}
export function localDate(seconds) {
  const date = new Date(seconds * 1000);
  const pad = n => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}
export function queryHash(filters) {
  const params = new URLSearchParams(Object.entries(filters).filter(([, value]) => value !== '' && value != null));
  return `#query${params.size ? `?${params}` : ''}`;
}
export function isIPAddress(value) {
  if (value.includes(':')) {
    if (!/^[0-9a-f:.]+$/i.test(value)) return false;
    try { new URL(`http://[${value}]/`); return true; } catch { return false; }
  }
  const octets = value.split('.');
  return octets.length === 4 && octets.every(octet => /^(0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255);
}
export function addressFilterError({ source = '', destination = '' }) {
  for (const [value, label, portLabel] of [[source, 'Source IP', 'Source port (sample)'], [destination, 'Destination IP', 'Destination port']]) {
    const address = value.trim();
    if (!address || isIPAddress(address)) continue;
    const portHint = /^\d+$/.test(address) && Number(address) <= 65535 ? ` To filter port ${Number(address)}, use ${portLabel}.` : '';
    return `${label} must be an IPv4 or IPv6 address.${portHint}`;
  }
  return '';
}
