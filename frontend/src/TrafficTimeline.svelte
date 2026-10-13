<script>
  import { formatNumber, formatBytes } from './analytics.js';
  export let summary;
  const series = [{key: 'packets', label: 'Observed', color: '#159b89'}, {key: 'passed', label: 'Passed', color: '#538bb7'}, {key: 'dropped', label: 'Blocked', color: '#d39b38'}];
  const date = at => new Date(at * 1000).toLocaleString();
  $: maximum = Math.max(1, ...summary.timeline.map(point => point.packets));
  $: span = Math.max(3600, summary.to - summary.from);
  $: x = at => 1000 * (at - summary.from) / span;
  $: y = count => 178 - count / maximum * 155;
  function path(points, key, x, y) {
    let previous = null;
    return points.map(point => {
      const command = previous !== null && point.at - previous === 3600 ? 'L' : 'M';
      previous = point.at;
      return `${command}${x(point.at)},${y(point[key])}`;
    }).join(' ');
  }
</script>

<div class="legend">{#each series as item}<span><i style:background={item.color}></i>{item.label}</span>{/each}<span class="units">Packets / hourly bucket</span></div>
<div class="chart">
  <div class="maximum">{formatNumber(maximum)}</div>
  <svg viewBox="-8 0 1016 190" preserveAspectRatio="none" role="img" aria-label="Hourly observed, passed, and blocked packets. Gaps indicate hours without retained data.">
    {#each [23, 100, 178] as line}<line x1="0" x2="1000" y1={line} y2={line} stroke="#e5edef" stroke-dasharray={line === 178 ? '' : '4 4'}/>{/each}
    {#each series as item}
      <path d={path(summary.timeline, item.key, x, y)} fill="none" stroke={item.color} stroke-width="2" vector-effect="non-scaling-stroke"/>
      {#if summary.timeline.length === 1}<circle cx={x(summary.timeline[0].at)} cy={y(summary.timeline[0][item.key])} r="3" fill={item.color}/>{/if}
    {/each}
    {#each summary.timeline as point}
      <circle cx={x(point.at)} cy={y(point.packets)} r={point.complete ? 2.5 : 4} fill={point.complete ? '#159b89' : '#d39b38'}><title>{date(point.at)}: {formatNumber(point.packets)} observed, {formatNumber(point.passed)} passed, {formatNumber(point.dropped)} blocked{point.complete ? '' : ' · Incomplete evidence'}</title></circle>
    {/each}
  </svg>
  <div class="axis"><span>{date(summary.from)}</span><span>{date(summary.to)}</span></div>
</div>
<details><summary>View hourly values</summary><div class="table-scroll"><table><thead><tr><th>Hour</th><th>Observed</th><th>Volume</th><th>Passed</th><th>Blocked</th><th>Evidence</th></tr></thead><tbody>{#each [...summary.timeline].reverse() as point}<tr><td>{date(point.at)}</td><td>{formatNumber(point.packets)}</td><td>{formatBytes(point.bytes)}</td><td>{formatNumber(point.passed)}</td><td>{formatNumber(point.dropped)}</td><td>{point.complete ? 'Complete' : 'Incomplete'}</td></tr>{/each}</tbody></table></div></details>

<style>
  .legend{display:flex;flex-wrap:wrap;align-items:center;gap:20px;padding:20px 24px 0;font-size:11px;color:#728794}.legend span{display:flex;align-items:center;gap:7px}.legend i{width:8px;height:8px;border-radius:50%;display:inline-block}.legend .units{margin-left:auto;color:#8d9ea7}.chart{padding:16px 24px 24px}.maximum{font-size:10px;color:#8d9ea7}svg{width:100%;height:220px}.axis{display:flex;justify-content:space-between;gap:20px;font-size:10px;color:#8d9ea7}details{border-top:1px solid #edf1f3}summary{cursor:pointer;padding:15px 24px;color:#118876;font-size:11px}.table-scroll{overflow:auto;max-height:300px}table{border-collapse:collapse;width:100%;font-size:11px;text-align:left;white-space:nowrap}th,td{padding:12px 22px;border-bottom:1px solid #edf1f3}th{font-size:9px;color:#8496a0;text-transform:uppercase}td{color:#536975}@media(max-width:700px){.legend{gap:12px}.legend .units{width:100%;margin:0}svg{height:180px}}
</style>
