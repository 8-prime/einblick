<script>
  import { onMount } from 'svelte';
  export let api;
  export let ip = '';
  export let from = 0;
  export let to = 0;
  export let statusOnly = false;
  let data = null, error = '', busy = false, request = 0, mounted = false, paged = false;
  let selection = '', fixedFrom = 0, fixedTo = 0;
  const time = at => at ? new Date(at * 1000).toLocaleString() : 'Waiting for first poll';
  async function load(more = false) {
    if (!mounted || (!statusOnly && (!ip || !to))) return;
    const current = ++request;
    busy = true; error = '';
    paged = more;
    if (!more) {fixedFrom = from; fixedTo = to;}
    try {
      const params = new URLSearchParams({from:String(fixedFrom),to:String(fixedTo),limit:'100'});
      if (more && data?.next_cursor) params.set('cursor',data.next_cursor);
      const result = await api(statusOnly ? '/caddy/status' : `/sources/${encodeURIComponent(ip)}/caddy?${params}`);
      if (current === request) data = more ? {...result,rows:[...data.rows,...result.rows]} : result;
    } catch (e) { if (current === request) error = e.message; }
    finally { if (current === request) busy = false; }
  }
  $: if (mounted && selection !== `${ip}:${to-from}`) {
    selection = `${ip}:${to-from}`; paged = false; data = null;
  }
  $: if (mounted && !paged) { to; load(); }
  onMount(() => {
    mounted = true;
    const timer = setInterval(() => {if (!busy && !paged) load();}, 5000);
    return () => {mounted = false; request++; clearInterval(timer);};
  });
</script>

<section class="caddy" aria-label={statusOnly ? 'Caddy integration status' : 'Caddy requests for this IP'}>
  <header><div><h2>{statusOnly ? 'Caddy integration' : 'Caddy · HTTP requests'}</h2><small>Access-log attribution{#if data?.enabled} · polled every {data.poll_seconds}s{/if}</small></div><button disabled={busy} onclick={()=>load()}>Refresh</button></header>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if data}
    {#if !data.enabled}<p>Caddy collection is disabled. Enable <code>[caddy]</code> and configure JSON access-log paths in einblick.toml.</p>{/if}
    {#each data.sources as source}
      <details open={statusOnly || !!source.error || !!source.skipped || !!source.gaps}>
        <summary><code>{source.log_path}</code> · {source.error || (!source.last_poll ? 'Waiting for first poll' : source.last_poll < Date.now()/1000 - Math.max(15,data.poll_seconds*3) ? 'Polling overdue' : 'Polling')}</summary>
        <p>Last successful poll: {time(source.last_success)} · Skipped records: {source.skipped} · File gaps / resets: {source.gaps}</p>
      </details>
    {/each}
    {#if !statusOnly}
      <p>Requests logged by Caddy for this remote IP in the selected time range. Packet protocol and port filters apply to the traffic table above. Query strings are omitted.</p>
      <div class="scroll"><table><thead><tr><th>Time</th><th>Application</th><th>Domain / host</th><th>Path</th><th>Method</th><th>Status</th></tr></thead><tbody>
        {#each data.rows as row (row.id)}<tr><td>{time(row.at)}</td><td><b>Caddy</b><small title={row.log_path}>Access log</small>{#if row.client_ip && row.client_ip !== row.remote_ip}<small>Reported client: <code>{row.client_ip}</code></small>{/if}</td><td><code>{row.host}</code></td><td class="path"><code>{row.path}</code></td><td>{row.method}</td><td>{row.status}</td></tr>{/each}
        {#if !data.rows.length}<tr><td colspan="6">{busy ? 'Loading requests…' : 'No retained Caddy requests for this IP and time range.'}</td></tr>{/if}
      </tbody></table></div>
      {#if data.next_cursor}<footer><button disabled={busy} onclick={()=>load(true)}>Load older requests</button></footer>{/if}
      <p>Retention: {data.retention_days} days, subject to the configured row cap. Hosts and paths are values logged by Caddy. Requests do not change packet counts or identify the upstream application.</p>
    {/if}
  {:else if busy}<p>Loading Caddy integration…</p>{/if}
</section>

<style>
  .caddy{border:1px solid #e0e7eb;border-radius:9px;background:white;margin:20px 0;overflow:hidden;color:#536975;font-size:12px}
  header{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:20px 24px;border-bottom:1px solid #edf1f3}h2{font-size:15px;margin:0 0 6px;color:#263b47}small{display:block;margin-top:5px;font-size:11px}
  p,details{margin:14px 24px;line-height:1.6;overflow-wrap:anywhere}details p{margin:8px 0}summary{cursor:pointer}code{font-family:ui-monospace,monospace;font-size:11px;overflow-wrap:anywhere}.scroll{overflow:auto;max-height:450px}table{border-collapse:collapse;width:100%;text-align:left}th,td{padding:14px 24px;border-bottom:1px solid #edf1f3;vertical-align:top}th{font-size:10px;background:#fbfcfc;text-transform:uppercase;color:#8a9ba5}.path{min-width:180px;max-width:500px;overflow-wrap:anywhere}footer{padding:14px 24px}.error{color:#af4141}
</style>
