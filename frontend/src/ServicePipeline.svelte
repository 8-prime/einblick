<script>
  export let service;
  export let health = {};
  export let selected = null;
  export let onselect = () => {};
  export let blocking = false;
  export let automatic = false;
  export let replay = null;
  $: rows = service.sources.flatMap(s => s.filters.map(f => ({source:s,filter:f})));
  $: height = Math.max(360, rows.length * 90 + 60, service.policies.length * 90 + 60);
  $: middle = height / 2;
  $: sourceNodes = service.sources.map(s => {
    const indices = rows.map((r,i) => r.source.id === s.id ? i : -1).filter(i => i >= 0);
    return {source:s,y:indices.length ? 55 + (indices[0]+indices.at(-1))/2*90 : middle};
  });
  const activePath = (type,id) => selected && (type==='source'?selected.source_id===id:type==='filter'?selected.filter_id===id:type==='policy'?selected.policy_id===id:false);
</script>
<div class="graph" aria-label="Generated service protection pipeline">
  <svg viewBox={`0 0 1380 ${height}`} role="img" aria-label="Sources flow through filters and service policies to the global ban manager and XDP">
    <defs><marker id="pipeline-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#8097a5"/></marker></defs>
    {#each rows as row,i}
      {@const y=55+i*90}
      {@const sy=sourceNodes.find(n=>n.source.id===row.source.id)?.y || middle}
      <path class:highlight={activePath('filter',row.filter.id) && selected.source_id===row.source.id} d={`M190 ${sy} C215 ${sy},215 ${y},240 ${y}`} marker-end="url(#pipeline-arrow)"/>
      <path class:highlight={activePath('filter',row.filter.id) && selected.source_id===row.source.id} d={`M415 ${y} C450 ${y},450 ${middle},485 ${middle}`} marker-end="url(#pipeline-arrow)"/>
      <foreignObject x="240" y={y-30} width="175" height="80"><button class:disabled={!service.enabled||!row.source.enabled||!row.filter.enabled} class:highlight={activePath('filter',row.filter.id) && selected.source_id===row.source.id} onclick={()=>onselect({type:'filter',id:row.filter.id,source:row.source.id})}><small>FILTER · {row.filter.event_type}</small>{row.filter.name}{#if replay}<small>{replay.filter_counts[`${row.source.id}:${row.filter.id}`]||0} retained events</small>{/if}</button></foreignObject>
    {/each}
    {#each sourceNodes as node}
      <foreignObject x="15" y={node.y-30} width="175" height="80"><button class:disabled={!service.enabled||!node.source.enabled} class:warning={health[node.source.id]?.error} class:highlight={activePath('source',node.source.id)} onclick={()=>onselect({type:'source',id:node.source.id})}><small>{node.source.input.kind.toUpperCase()} · {health[node.source.id]?.status || 'waiting'}</small>{node.source.name}{#if replay}<small>{replay.source_counts[node.source.id]||0} retained events</small>{/if}</button></foreignObject>
    {/each}
    <foreignObject x="485" y={middle-35} width="180" height="75"><button class:disabled={!service.enabled} onclick={()=>onselect({type:'service'})}><small>SERVICE · {service.enabled?'enabled':'disabled'}</small>{service.name}</button></foreignObject>
    {#each service.policies as policy,i}
      {@const y=middle+(i-(service.policies.length-1)/2)*90}
      <path class:highlight={activePath('policy',policy.id)} d={`M665 ${middle} C700 ${middle},700 ${y},735 ${y}`} marker-end="url(#pipeline-arrow)"/>
      <path class:highlight={activePath('policy',policy.id)} d={`M910 ${y} C945 ${y},945 ${middle},980 ${middle}`} marker-end="url(#pipeline-arrow)"/>
      <foreignObject x="735" y={y-30} width="175" height="80"><button class:disabled={!service.enabled||!policy.enabled} class:highlight={activePath('policy',policy.id)} onclick={()=>onselect({type:'policy',id:policy.id})}><small>POLICY · {service.observe_only||policy.observe_only?'observe':'enforce'}</small>{policy.name}{#if replay}<small>{replay.policy_counts[policy.id]||0} hypothetical decisions</small>{/if}</button></foreignObject>
    {/each}
    <foreignObject x="980" y={middle-35} width="175" height="75"><button onclick={()=>onselect({type:'enforcement'})}><small>GLOBAL BAN MANAGER</small>{automatic?'Automatic':'Observe / manual'}<small>{replay?`${replay.potentially_preventable} potentially preventable events`:'Allowlists & health checks'}</small></button></foreignObject>
    <path d={`M1155 ${middle} L1200 ${middle}`} marker-end="url(#pipeline-arrow)"/>
    <foreignObject x="1200" y={middle-35} width="165" height="75"><button onclick={()=>onselect({type:'enforcement'})}><small>eBPF / XDP</small>{blocking?'Blocking enabled':'Observe mode'}<small>Whole source IP</small></button></foreignObject>
  </svg>
</div>
<style>
  .graph{overflow:auto;padding:18px;background:#f9fbfc;border:1px solid #e0e7eb;border-radius:8px}.graph svg{display:block;width:100%;min-width:1050px}path{fill:none;stroke:#a7b7c0;stroke-width:1.5}path.highlight{stroke:#b44747;stroke-width:3}button{width:100%;height:100%;text-align:left;font-size:12px;overflow:hidden;overflow-wrap:anywhere;border-radius:7px;padding:8px 12px;background:white}small{display:block;font-size:9px;color:#748895;margin-bottom:4px}button.disabled{opacity:.5;border-style:dashed}button.warning{border-color:#c99742;background:#fff7e8}button.highlight{border-color:#b44747;background:#fff2f2}
</style>
