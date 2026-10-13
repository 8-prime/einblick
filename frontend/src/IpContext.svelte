<script>
  export let info = null;
  export let compact = false;
</script>

{#if info}
  <small class="ip-context" title={info.organization || ''}>
    {compact ? (info.country_code || info.country || 'Country unknown') : (info.country || info.country_code || 'Country unknown')}
    {#if info.asn} · AS{info.asn}{/if}
    {#if !compact && info.organization}<span>{info.organization}</span>{/if}
  </small>
{:else}
  <small class="ip-context">Country / ASN unavailable</small>
{/if}

<style>
  .ip-context{display:block;margin-top:6px;font-size:11px;color:#6a7d89;line-height:1.5;white-space:normal;overflow-wrap:anywhere}
  .ip-context span{display:block}
</style>
