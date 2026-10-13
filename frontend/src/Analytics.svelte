<script>
  import { drilldown } from './query.js';
  import { onMount } from 'svelte';
  import RankedTraffic from './RankedTraffic.svelte';
  import TrafficTimeline from './TrafficTimeline.svelte';
  import { formatNumber, formatBytes, percentage } from './analytics.js';
  export let api;
  export let onQuery;
  function query(kind, row) { onQuery({...drilldown(kind, row.key), from:data.from, to:data.to + 3599}); }
  let range = '86400', metric = 'packets', data = null, loading = false, error = '', request = 0;
  async function load(clear = false) {
    const id = ++request;
    loading = true; error = '';
    if (clear) data = null;
    const to = Math.floor(Date.now() / 1000);
    try {
      const result = await api(`/analytics?from=${to - Number(range)}&to=${to}`);
      if (id === request) data = result;
    } catch (e) { if (id === request) error = e.message; }
    finally { if (id === request) loading = false; }
  }
  onMount(() => { load(); const refresh = setInterval(() => { if (!loading) load(); }, 60000); return () => { request++; clearInterval(refresh); }; });
</script>

<div class="toolbar">
  <div><h2>Explore your traffic</h2><p>Retained hourly history · select a country, network, protocol, or port to query its traffic</p></div>
  <div class="filters"><label>Range<select bind:value={range} onchange={() => load(true)}><option value="86400">Last 24 hours</option><option value="604800">Last 7 days</option><option value="2592000">Last 30 days</option></select></label><label>Rank countries & networks by<select bind:value={metric}><option value="packets">Packets</option><option value="bytes">Bytes</option></select></label><button disabled={loading} onclick={() => load()}>{loading ? 'Refreshing…' : 'Refresh ↻'}</button></div>
</div>
{#if error}<p class="error" role="alert">{error}{#if data} · Showing the last successful result.{/if}</p>{/if}
{#if data}
  <div class="cards">
    <article><span>OBSERVED PACKETS</span><strong>{formatNumber(data.totals.packets)}</strong><small>Across retained hours in this range</small></article>
    <article><span>INCOMING VOLUME</span><strong>{formatBytes(data.totals.bytes)}</strong><small>{formatNumber(data.timeline.length)} hourly buckets</small></article>
    <article><span>BLOCKED SHARE</span><strong>{percentage(data.totals.dropped, data.totals.packets)}</strong><small>{formatNumber(data.totals.dropped)} packets blocked by Einblick</small></article>
    <article><span>COUNTRY COVERAGE</span><strong>{percentage(data.country_mapped[metric], data.totals[metric])}</strong><small>Of observed {metric} mapped to a country</small></article>
  </div>
  <div class="coverage" class:warning={data.incomplete_buckets > 0 || data.missing_buckets > 0}>
    {#if data.timeline.length}Available buckets: {new Date(data.timeline[0].at * 1000).toLocaleString()} – {new Date(data.timeline.at(-1).at * 1000).toLocaleString()}.{/if}
    {formatNumber(data.missing_buckets)} hours without retained buckets · {formatNumber(data.incomplete_buckets)} buckets with incomplete evidence. Counts include whole overlapping hours; the latest hour includes persisted minutes so far. Missing hours are gaps, not zero traffic.
  </div>
  {#if data.timeline.length}
    <section class="panel"><div class="heading"><h2>Traffic over time</h2><span class="tag">HOURLY</span></div><TrafficTimeline summary={data}/></section>
    <div class="grid">
      <section class="panel"><div class="heading"><h2>Traffic by country</h2><span class="tag">{metric.toUpperCase()}</span></div><RankedTraffic rows={data.countries} {metric} total={data.totals[metric]} label="Country" otherLabel="Other mapped countries" selectable={row => !!drilldown('country', row.key)} onSelect={row => query('country', row)}/><footer>Approximate current country mapping. {percentage(data.source_tracked[metric], data.totals[metric])} of observed {metric} represented in retained source summaries.</footer></section>
      <section class="panel"><div class="heading"><h2>Top networks / ASNs</h2><span class="tag">{metric.toUpperCase()}</span></div><RankedTraffic rows={data.networks} {metric} total={data.totals[metric]} label="Network" otherLabel="Other mapped networks" selectable={row => !!drilldown('network', row.key)} onSelect={row => query('network', row)}/><footer>Current network ownership from DB-IP Lite. One network may span several countries.</footer></section>
      <section class="panel"><div class="heading"><h2>Protocol mix</h2><span class="tag">PACKETS</span></div><RankedTraffic rows={data.protocols} total={data.totals.packets} label="Protocol" otherLabel="Other protocols" selectable={row => !!drilldown('protocol', row.key)} onSelect={row => query('protocol', row)}/><footer>Packet shares include traffic without retained protocol detail.</footer></section>
      <section class="panel"><div class="heading"><h2>Top destination ports</h2><span class="tag">PACKETS</span></div><RankedTraffic rows={data.ports} total={data.totals.packets} label="Port / protocol" otherLabel="Other destination ports" selectable={row => !!drilldown('port', row.key)} onSelect={row => query('port', row)}/><footer>Ingress destination before host firewall/NAT. Port zero is grouped with unparsed/no-port traffic in these summaries.</footer></section>
    </div>
    <p class="footnote">Countries and networks use the top 100 retained sources per hour, so rankings are approximate. Unavailable mappings and other/untracked sources remain visible. Passed packets passed Einblick; these counts do not confirm service delivery.</p>
  {:else}<section class="panel empty"><h2>No retained traffic in this range.</h2><p>The first partial hour appears after the next minute checkpoint. Try a longer range if older history is available.</p></section>{/if}
{:else if loading}<section class="panel empty" role="status">Loading traffic analytics…</section>{/if}

<style>
  h2{font-size:15px;font-weight:600;margin:0}.toolbar{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:22px}.toolbar p{margin:8px 0 0;font-size:11px;color:#8797a1}.filters{display:flex;align-items:end;gap:12px}.filters label{font-size:10px}.filters select{font-size:11px;padding:8px}.filters button{font-size:11px;white-space:nowrap}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:24px 0}.cards article{background:white;border:1px solid #e1e7eb;border-radius:9px;padding:23px}.cards article>span{font-size:9px;font-weight:700;letter-spacing:1.3px;color:#82949e}.cards strong{font-size:30px;font-weight:550;letter-spacing:-1px;display:block;margin:15px 0 7px}.cards small{font-size:11px;line-height:1.5;display:block}.coverage{padding:14px 18px;background:#edf5f2;border:1px solid #d2e5de;color:#548476;border-radius:7px;line-height:1.7;font-size:11px;margin-bottom:22px}.coverage.warning{background:#fff8ed;border-color:#eadbc3;color:#9b7a43}.panel{border:1px solid #e0e7eb;border-radius:9px;background:white;overflow:hidden;margin-bottom:20px}.heading{display:flex;justify-content:space-between;align-items:center;padding:22px 24px;border-bottom:1px solid #edf1f3;gap:15px}.tag{background:#edf5f2;color:#3f8c7f;font-size:9px;padding:5px 8px;border-radius:4px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.grid .panel{margin-bottom:0}footer{padding:14px 24px;font-size:11px;color:#8797a1;line-height:1.6}.footnote{font-size:11px;color:#91a0a9;margin-top:20px;line-height:1.7}.empty{padding:60px 24px;text-align:center;color:#8797a1}.empty p{font-size:12px;line-height:1.7}.error{color:#af4141;font-size:12px}@media(max-width:1100px){.cards{grid-template-columns:repeat(2,1fr)}.toolbar{flex-wrap:wrap}.grid{grid-template-columns:1fr}}@media(max-width:700px){.filters{flex-wrap:wrap;width:100%}.filters label{flex:1;min-width:120px}.cards{gap:10px}.cards article{padding:17px}.cards strong{font-size:26px}.heading{padding:18px}.empty{padding:40px 18px}}
</style>
