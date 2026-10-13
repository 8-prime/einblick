<script>
  import { formatNumber, formatBytes, percentage, rankingRows } from './analytics.js';
  export let rows = [];
  export let metric = 'packets';
  export let total = 0;
  export let limit = 8;
  export let label = 'Group';
  export let otherLabel = 'Other tracked traffic';
  $: ranked = rankingRows(rows, metric, limit);
  $: max = Math.max(1, ...ranked.map(row => row[metric]));
</script>

{#if ranked.length}
  <table>
    <thead><tr><th>{label}</th><th>{metric === 'bytes' ? 'Volume' : 'Packets'}</th><th>Share</th></tr></thead>
    <tbody>{#each ranked as row (row.key)}
      <tr class:muted={['unknown', 'untracked', 'other', 'none'].includes(row.key)}>
        <td><span class="row-label" title={row.key === 'other' ? otherLabel : row.label}>{row.key === 'other' ? otherLabel : row.label}</span><div class="track" aria-hidden="true"><span style:width={`${row[metric] / max * 100}%`}></span></div></td>
        <td class="number">{metric === 'bytes' ? formatBytes(row.bytes) : formatNumber(row.packets)}</td>
        <td class="share">{percentage(row[metric], total)}</td>
      </tr>
    {/each}</tbody>
  </table>
{:else}
  <div class="empty">No retained traffic in this range.</div>
{/if}

<style>
  table{width:100%;border-collapse:collapse;font-size:12px;text-align:left}th{background:#fbfcfc;color:#8496a0;text-transform:uppercase;font-size:9px;letter-spacing:1px;font-weight:600;padding:13px 22px}td{padding:13px 22px;border-bottom:1px solid #edf1f3;color:#536975}td:first-child{width:65%}.row-label{display:block;overflow-wrap:anywhere;line-height:1.5}.number,.share{white-space:nowrap;text-align:right;font-variant-numeric:tabular-nums}.share{color:#82959f}.track{margin-top:8px;background:#f0f6f4;height:4px;border-radius:4px;overflow:hidden}.track span{display:block;height:100%;background:#22a994;border-radius:4px}.muted .track span{background:#9bb0ba}.muted .row-label{color:#7b8e99}.empty{padding:50px 24px;text-align:center;color:#8d9ea7;font-size:12px}@media(max-width:700px){th,td{padding:12px 16px}.share{padding-left:0}td:first-child{width:auto}}
</style>
