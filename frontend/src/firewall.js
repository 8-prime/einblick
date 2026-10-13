import { isIPAddress } from './query.js';

function addressNumber(ip) {
  if (!isIPAddress(ip)) return null;
  if (!ip.includes(':')) return { bits:32, value:ip.split('.').reduce((value, octet) => (value << 8n) | BigInt(octet), 0n) };
  const [head, tail] = new URL(`http://[${ip}]/`).hostname.slice(1, -1).split('::');
  const first = head ? head.split(':') : [], last = tail ? tail.split(':') : [];
  const groups = tail === undefined ? first : [...first, ...Array(8 - first.length - last.length).fill('0'), ...last];
  return { bits:128, value:groups.reduce((value, group) => (value << 16n) | BigInt(`0x${group}`), 0n) };
}

export function networkContains(network, ip) {
  const [base, prefix, extra] = network.split('/');
  if (extra !== undefined || !/^\d+$/.test(prefix ?? '')) return false;
  const address = addressNumber(ip), subnet = addressNumber(base), bits = Number(prefix);
  if (!address || !subnet || address.bits !== subnet.bits || bits > address.bits) return false;
  const shift = BigInt(address.bits - bits);
  return (address.value >> shift) === (subnet.value >> shift);
}

export function matchingRules(rules, ip) {
  return rules.filter(rule => networkContains(rule.network, ip));
}

export function ruleIsActive(rule, now) {
  return rule.enabled && (rule.expires == null || rule.expires > now);
}

export function ruleStatus(rule, now) {
  if (!rule.enabled) return 'Removed';
  if (rule.expires != null && rule.expires <= now) return 'Expired';
  if (rule.error) return 'Failed';
  return rule.applied ? 'Applied' : 'Inactive / pending';
}
