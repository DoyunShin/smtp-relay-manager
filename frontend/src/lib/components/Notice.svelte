<script lang="ts">
  export let kind: 'error' | 'success' | 'info' = 'info';
  export let message = '';
</script>

{#if message}
  <div class:notice-error={kind === 'error'} class:notice-success={kind === 'success'} class="notice" role={kind === 'error' ? 'alert' : 'status'}>
    {message}
  </div>
{/if}
