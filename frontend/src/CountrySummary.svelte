<script>
  import RankedTraffic from './RankedTraffic.svelte';
  import { liveCountries, percentage } from './analytics.js';
  export let snapshot;
  export let onExplore;
  $: countries = liveCountries(snapshot);
</script>

<section class="panel">
  <div class="heading"><div><h2>Traffic by country</h2><small>Current process · retained source summary</small></div><button onclick={onExplore}>Explore analytics ↗</button></div>
  <RankedTraffic rows={countries.rows} total={countries.totals.packets} label="Country" otherLabel="Other mapped countries" limit={5}/>
  <footer>{percentage(countries.mappedPackets, countries.totals.packets)} of observed packets mapped to a country. Approximate current IP mapping.</footer>
</section>

<style>
  .panel{border:1px solid #e0e7eb;border-radius:9px;background:white;overflow:hidden;margin-bottom:20px}.heading{display:flex;justify-content:space-between;align-items:center;gap:15px;padding:22px 24px;border-bottom:1px solid #edf1f3}h2{font-size:15px;font-weight:600;margin:0}small{display:block;margin-top:7px;font-size:11px;color:#8797a1}button{border:0;background:none;padding:4px;font-size:11px;color:#118876;white-space:nowrap}footer{padding:14px 24px;font-size:11px;color:#8797a1;line-height:1.6}@media(max-width:700px){.heading{padding:18px;align-items:flex-start;flex-wrap:wrap}}
</style>
