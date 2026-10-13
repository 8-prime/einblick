<script>
  import { onMount } from 'svelte';
  import IpContext from './IpContext.svelte';
  import { formatNumber, formatBytes } from './analytics.js';
  import { localDate, queryHash } from './query.js';
  export let api;
  export let initial = {};
  export let onSource;
  export let onFilters;
  let source = initial.source || '', destination = initial.destination || '', country = initial.country || '', asn = initial.asn || '', organization = initial.organization || '', port = initial.port ?? '', source_port = initial.source_port ?? '', protocol = initial.protocol ?? '', iface = initial.interface || '';
  let range = initial.from ? 'custom' : '86400';
  const now = Math.floor(Date.now() / 1000);
  let from = localDate(Number(initial.from || now - 86400)), to = localDate(Number(initial.to || now));
  let result = null, loading = false, error = '', request = 0, applied = null;
  const time = seconds => new Date(seconds * 1000).toLocaleString();
  const protocolName = p => ({6:'TCP',17:'UDP',1:'ICMP',58:'ICMPv6'})[p] || `IP ${p}`;
  async function run(more = false) {
    const id = ++request;
    loading = true; error = '';
    if (!more) {
      const end = range === 'custom' ? Math.floor(new Date(to).getTime() / 1000) : Math.floor(Date.now() / 1000);
      const start = range === 'custom' ? Math.floor(new Date(from).getTime() / 1000) : end - Number(range);
      if (!Number.isFinite(start) || !Number.isFinite(end) || start > end || end - start > 7776000) {error = 'Choose a valid time range of up to 90 days.'; loading = false; return;}
      applied = Object.fromEntries(Object.entries({source:source.trim(), destination:destination.trim(), country:country.trim().toLowerCase() === 'unknown' ? 'unknown' : country.trim().toUpperCase(), asn, organization:organization.trim(), port, source_port, protocol, interface:iface.trim(), from:start, to:end, resolution:end-start>604800?'hour':'minute'}).filter(([, v]) => v !== '' && v != null));
      onFilters(applied);
      window.history.replaceState(null, '', queryHash(applied));
      result = null;
    }
    const params = new URLSearchParams({...applied, limit:'100'});
    if (more && result?.next_cursor) params.set('cursor', result.next_cursor);
    try {
      const data = await api(`/traffic?${params}`);
      if (id === request) result = more ? {...data, rows:[...result.rows, ...data.rows], sources:{...result.sources,...data.sources}} : data;
    } catch (e) { if (id === request) error = e.message; }
    finally { if (id === request) loading = false; }
  }
  function clear() {
    source = destination = country = asn = organization = port = source_port = protocol = iface = '';
    range = '86400'; run();
  }
  onMount(() => { run(); return () => { request++; }; });
  $: totals = (result?.rows || []).reduce((sum, row) => ({packets:sum.packets+row.packets,bytes:sum.bytes+row.bytes,dropped:sum.dropped+row.dropped}), {packets:0,bytes:0,dropped:0});
</script>

<section class="panel">
  <div class="heading"><div><h2>Query traffic</h2><p>Combine filters to find the sources and services behind your traffic.</p></div><button onclick={clear} disabled={loading}>Clear filters</button></div>
  <form onsubmit={e => {e.preventDefault();run();}}>
    <label>Country code<input bind:value={country} placeholder="CN, DE, US or unknown" list="query-countries" maxlength="7"></label>
    <datalist id="query-countries"><option value="CN">China</option><option value="DE">Germany</option><option value="US">United States</option><option value="unknown">Country unavailable</option></datalist>
    <label>ISP / network<input bind:value={organization} placeholder="Organization contains…" maxlength="200"></label>
    <label>ASN<input type="number" min="0" max="4294967295" bind:value={asn} placeholder="e.g. 4134"></label>
    <label>Source IP<input bind:value={source} placeholder="IPv4 or IPv6"></label>
    <label>Target IP<input bind:value={destination} placeholder="IPv4 or IPv6"></label>
    <label>Interface<input bind:value={iface} placeholder="e.g. eth0" maxlength="128"></label>
    <label>Protocol<select bind:value={protocol}><option value="">All protocols</option><option value="6">TCP</option><option value="17">UDP</option><option value="1">ICMP</option><option value="58">ICMPv6</option>{#if protocol !== '' && !['6','17','1','58'].includes(String(protocol))}<option value={protocol}>IP {protocol}</option>{/if}</select></label>
    <label>Target port<input type="number" min="0" max="65535" bind:value={port} placeholder="All ports"></label>
    <label>Source port (sample)<input type="number" min="0" max="65535" bind:value={source_port} placeholder="All ports"></label>
    <label>Time range<select bind:value={range}><option value="3600">Last hour</option><option value="86400">Last 24 hours</option><option value="604800">Last 7 days</option><option value="2592000">Last 30 days</option><option value="7776000">Last 90 days</option><option value="custom">Custom range</option></select></label>
    {#if range === 'custom'}<label>From (local time)<input type="datetime-local" step="1" required bind:value={from}></label><label>To (local time)<input type="datetime-local" step="1" required bind:value={to}></label>{/if}
    <div class="actions"><button class="primary" disabled={loading}>{loading ? 'Searching…' : 'Search traffic →'}</button></div>
  </form>
</section>
{#if error}<p class="error" role="alert">{error}</p>{/if}
{#if result}
  <div class="summary" aria-live="polite"><strong>{formatNumber(result.rows.length)} loaded groups</strong><span>{formatNumber(totals.packets)} packets</span><span>{formatBytes(totals.bytes)}</span><span>{formatNumber(totals.dropped)} dropped</span></div>
  <p class="scope">{time(applied.from)} – {time(applied.to)} · {applied.resolution === 'hour' ? 'Hourly' : 'Minute'} buckets · Totals above cover loaded groups{result.next_cursor ? '; more groups available' : ''}.</p>
  {#each result.warnings as warning}<p class="warning">{warning}</p>{/each}
  <section class="panel">
    <div class="table-scroll"><table><thead><tr><th>Source / country / network</th><th>Target / interface</th><th>Protocol / ports</th><th>Application / service</th><th>Packets / volume</th><th>TCP indicators</th><th>Passed / dropped</th><th>First / last seen</th></tr></thead><tbody>
      {#each result.rows as row}
        <tr><td><button class="link mono" onclick={() => onSource(row.source)}>{row.source}</button><IpContext info={result.sources[row.source]}/></td><td class="mono">{row.destination}<small>{row.interface}</small></td><td>{protocolName(row.protocol)} / {row.port === null ? 'unparsed / none' : row.port}<small>Source ports: {row.source_ports.join(', ') || 'none'}{row.source_ports_truncated ? ' · sample truncated' : ''}</small></td><td>{#each row.application_attribution?.applications || [] as app}<details><summary>{app.name}</summary><small>{app.service || app.executable || app.method}{app.pid ? ` · PID ${app.pid}` : ''}</small><small>Observed {time(app.observed_from)} – {time(app.observed_to)}</small></details>{:else}Unknown{/each}<small>{row.application_attribution?.reasons?.map(reason => reason.replaceAll('_',' ')).join(' · ')}</small></td><td>{formatNumber(row.packets)}<small>{formatBytes(row.bytes)}</small></td><td>{formatNumber(row.syns)} SYN<small>{formatNumber(row.syn_acks)} SYN/ACK · {formatNumber(row.resets)} RST</small></td><td>{formatNumber(row.passed)} passed<small>{formatNumber(row.dropped)} dropped</small></td><td>{time(row.first_seen)}<small>{time(row.last_seen)}</small></td></tr>
      {:else}<tr><td class="empty" colspan="8">No retained traffic matches these filters. Try a wider range or remove a filter; check the coverage messages above.</td></tr>{/each}
    </tbody></table></div>
    <footer><span>Available persisted buckets: {result.available_from ? time(result.available_from) : 'none'} – {result.available_to ? time(result.available_to) : 'none'}</span>{#if result.next_cursor}<button disabled={loading} onclick={() => run(true)}>Load more groups</button>{/if}</footer>
  </section>
{:else if loading}<p role="status">Searching retained traffic…</p>{/if}
<p class="scope">Filters run before pagination. Counts include whole overlapping buckets and traffic groups; raw packets are not stored. Country and network use current IP mappings. Source-port samples may be incomplete. Application ownership identifies potential targets; passing Einblick does not confirm delivery.</p>

<style>
  .panel{background:white;border:1px solid #e0e7eb;border-radius:9px;overflow:hidden;margin-bottom:20px}.heading{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:22px 24px;border-bottom:1px solid #edf1f3}h2{font-size:15px;margin:0}.heading p{font-size:12px;color:#8797a1;margin:8px 0 0}form{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px;padding:24px}form input,form select{width:100%;font-size:12px}.actions{display:flex;align-items:end}.primary{background:#169984;color:white;border:0}.summary{display:flex;gap:24px;flex-wrap:wrap;font-size:13px}.scope{font-size:11px;color:#8797a1;line-height:1.7}.warning{background:#fff8ed;border:1px solid #eadbc3;color:#9b7a43;border-radius:7px;padding:12px 18px;font-size:12px;line-height:1.6}.error{color:#af4141}.table-scroll{overflow:auto;max-height:640px}table{border-collapse:collapse;width:100%;font-size:12px;text-align:left}th,td{padding:15px 20px;border-bottom:1px solid #edf1f3}th{font-size:9px;text-transform:uppercase;letter-spacing:1px;color:#8496a0;background:#fbfcfc}td{color:#536975;min-width:130px;vertical-align:top}small{display:block;margin-top:7px;font-size:11px;line-height:1.5;overflow-wrap:anywhere}.mono{font-family:ui-monospace,monospace;font-size:11px}.link{border:0;background:none;color:#118876;padding:0;text-align:left;text-decoration:underline;text-underline-offset:3px}details{margin-bottom:7px}summary{cursor:pointer}footer{padding:16px 24px;display:flex;justify-content:space-between;gap:16px;align-items:center;font-size:11px;color:#8797a1}.empty{text-align:center;padding:50px 24px}@media(max-width:1100px){form{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:700px){form{grid-template-columns:1fr;padding:18px}.heading{align-items:flex-start;flex-wrap:wrap;padding:18px}.summary{gap:12px}footer{flex-wrap:wrap}}
</style>
