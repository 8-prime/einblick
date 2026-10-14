<script>
  export let health;
  const time = value => value ? new Date(value * 1000).toLocaleString() : '—';
</script>

{#if health?.hosts?.length}
  <section class="panel" aria-label="Management DNS status">
    <div class="title"><h2>Management hostnames</h2><span class:warning={!health.ready}>{health.ready ? 'Resolved' : 'Automatic bans suspended'}</span></div>
    <div class="scroll"><table>
      <thead><tr><th>Hostname</th><th>Protected addresses</th><th>Last success</th><th>Status</th></tr></thead>
      <tbody>{#each health.hosts as host}
        <tr><td class="mono">{host.hostname}</td><td class="mono">{host.networks.join(', ') || 'None'}</td><td>{time(host.last_success)}</td><td class:warning={!!host.error}>{host.error || 'Resolved'}{#if host.error && host.networks.length}<small>Last resolved addresses retained temporarily.</small>{/if}</td></tr>
      {/each}</tbody>
    </table></div>
    <p>Refresh every {health.refresh_seconds}s. Failed lookups retain addresses for up to {health.stale_seconds}s after the last success. New automatic bans resume when all names resolve.</p>
  </section>
{/if}

<style>
  .panel{background:white;border:1px solid #e4eaed;border-radius:6px;margin-bottom:24px;overflow:hidden;color:#435f70}
  .title{padding:20px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px;border-bottom:1px solid #edf1f3}
  h2{margin:0;font-size:15px}span{font-size:11px}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:12px;text-align:left}
  th,td{padding:14px 24px;border-bottom:1px solid #edf1f3;vertical-align:top}th{font-size:10px;color:#8b9da8;text-transform:uppercase}
  .mono{font-family:monospace;overflow-wrap:anywhere}.warning{color:#a66c24}small{display:block;margin-top:5px}p{margin:0;padding:16px 24px;font-size:11px;line-height:1.6;color:#7c919e}
</style>
