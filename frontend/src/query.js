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
