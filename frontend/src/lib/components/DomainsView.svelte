<script lang="ts">
  import { api, errorMessage } from '$lib/api';
  import { formatDate } from '$lib/time';
  import type { Domain, User } from '$lib/types';
  import Notice from './Notice.svelte';

  export let user: User;
  export let onSelect: (id: string) => void;

  let domains: Domain[] = [];
  let name = '';
  let loading = true;
  let saving = false;
  let error = '';
  let success = '';

  const statusText: Record<Domain['status'], string> = {
    pending: '승인 대기',
    approved: '사용 중',
    rejected: '반려됨'
  };

  async function load(): Promise<void> {
    loading = true;
    error = '';
    try {
      domains = await api<Domain[]>('/domains');
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      loading = false;
    }
  }

  async function createDomain(): Promise<void> {
    saving = true;
    error = '';
    success = '';
    try {
      const domain = await api<Domain>('/domains', {
        method: 'POST',
        body: JSON.stringify({ name: name.trim().toLowerCase() })
      });
      domains = [domain, ...domains];
      name = '';
      success = '도메인 등록을 신청했습니다. 운영자 승인 후 발송할 수 있습니다.';
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      saving = false;
    }
  }

  async function decide(domain: Domain, action: 'approve' | 'reject'): Promise<void> {
    error = '';
    try {
      const updated = await api<Domain>(`/domains/${domain.id}/${action}`, { method: 'POST' });
      domains = domains.map((item) => (item.id === updated.id ? updated : item));
    } catch (caught) {
      error = errorMessage(caught);
    }
  }

  load();
</script>

<svelte:head><title>도메인 | SMTP Relay Manager</title></svelte:head>

<div class="page-heading">
  <div>
    <p class="eyebrow">DOMAINS</p>
    <h1>도메인</h1>
    <p class="muted">릴레이에 사용할 도메인을 등록하고 권한을 관리합니다.</p>
  </div>
</div>

<Notice kind="error" message={error} />
<Notice kind="success" message={success} />

<section class="panel compact-panel" aria-labelledby="register-domain">
  <div>
    <h2 id="register-domain">새 도메인 신청</h2>
    <p class="muted small">운영자가 승인하기 전에는 SMTP 발송에 사용할 수 없습니다.</p>
  </div>
  <form class="inline-form" on:submit|preventDefault={createDomain}>
    <label class="sr-only" for="domain-name">도메인 이름</label>
    <input id="domain-name" bind:value={name} placeholder="example.com" inputmode="url" required />
    <button class="primary" type="submit" disabled={saving}>{saving ? '신청 중…' : '등록 신청'}</button>
  </form>
</section>

{#if loading}
  <div class="empty-state">도메인을 불러오는 중입니다.</div>
{:else if domains.length === 0}
  <div class="empty-state">등록된 도메인이 없습니다.</div>
{:else}
  <section class="card-grid" aria-label="도메인 목록">
    {#each domains as domain}
      <article class="domain-card">
        <div class="card-topline">
          <span class:status-ok={domain.status === 'approved'} class:status-warn={domain.status === 'pending'} class:status-off={domain.status === 'rejected'} class="status-pill">
            {statusText[domain.status]}
          </span>
          <span class="muted small">소유자 {domain.owner_username}</span>
        </div>
        <h2>{domain.name}</h2>
        <p class="muted small">등록 {formatDate(domain.created_at)}</p>
        <div class="button-row">
          <button class="secondary" type="button" on:click={() => onSelect(domain.id)}>관리</button>
          {#if user.is_operator && domain.status === 'pending'}
            <button class="primary" type="button" on:click={() => decide(domain, 'approve')}>승인</button>
            <button class="danger-text" type="button" on:click={() => decide(domain, 'reject')}>반려</button>
          {/if}
        </div>
      </article>
    {/each}
  </section>
{/if}
