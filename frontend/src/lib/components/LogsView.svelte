<script lang="ts">
  import { api, errorMessage } from '$lib/api';
  import { formatDateTime } from '$lib/time';
  import type { DeliveryLog, DeliveryStatus, Domain, PageData } from '$lib/types';
  import Notice from './Notice.svelte';

  const limit = 30;
  let logs: PageData<DeliveryLog> = { items: [], total: 0, limit, offset: 0 };
  let domains: Domain[] = [];
  let domainId = '';
  let status: '' | DeliveryStatus = '';
  let sender = '';
  let recipient = '';
  let loading = true;
  let error = '';

  const statusLabel: Record<DeliveryStatus, string> = {
    pending: '처리 중',
    accepted: '접수 완료',
    failed: '실패',
    unknown: '결과 불명'
  };

  async function load(offset = 0): Promise<void> {
    loading = true;
    error = '';
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (domainId) params.set('domain_id', domainId);
    if (status) params.set('status', status);
    if (sender.trim()) params.set('sender', sender.trim());
    if (recipient.trim()) params.set('recipient', recipient.trim());
    try {
      logs = await api<PageData<DeliveryLog>>(`/logs?${params}`);
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      loading = false;
    }
  }

  async function initialize(): Promise<void> {
    try {
      domains = await api<Domain[]>('/domains');
    } catch {
      domains = [];
    }
    await load();
  }

  function domainName(id: string | null): string {
    if (!id) return '삭제된 도메인';
    return domains.find((domain) => domain.id === id)?.name ?? id;
  }

  initialize();
</script>

<svelte:head><title>발송 기록 | SMTP Relay Manager</title></svelte:head>

<div class="page-heading">
  <div>
    <p class="eyebrow">DELIVERY LOGS</p>
    <h1>발송 기록</h1>
    <p class="muted">외부 SMTP 서버로 전달한 결과를 확인합니다. 본문과 첨부파일은 저장하지 않습니다.</p>
  </div>
</div>

<Notice kind="error" message={error} />

<section class="panel filter-panel" aria-labelledby="filter-title">
  <h2 id="filter-title" class="sr-only">기록 필터</h2>
  <form class="filter-grid" on:submit|preventDefault={() => load(0)}>
    <label>도메인<select bind:value={domainId}><option value="">전체</option>{#each domains as domain}<option value={domain.id}>{domain.name}</option>{/each}</select></label>
    <label>상태<select bind:value={status}><option value="">전체</option>{#each Object.entries(statusLabel) as [value, label]}<option value={value}>{label}</option>{/each}</select></label>
    <label>발신 주소<input bind:value={sender} type="search" placeholder="sender@example.com" /></label>
    <label>수신 주소<input bind:value={recipient} type="search" placeholder="recipient@example.net" /></label>
    <button class="primary filter-button" type="submit">조회</button>
  </form>
</section>

<section class="panel table-panel" aria-label="발송 기록 목록">
  {#if loading}
    <div class="empty-state">기록을 불러오는 중입니다.</div>
  {:else if logs.items.length === 0}
    <div class="empty-state">조건에 맞는 발송 기록이 없습니다.</div>
  {:else}
    <div class="table-scroll">
      <table>
        <thead><tr><th>시각</th><th>도메인</th><th>발신</th><th>수신</th><th>상태</th><th>오류</th></tr></thead>
        <tbody>
          {#each logs.items as log}
            <tr>
              <td class="nowrap">{formatDateTime(log.created_at)}</td>
              <td>{domainName(log.domain_id)}</td>
              <td><code>{log.sender}</code></td>
              <td><span title={log.recipients.join(', ')}>{log.recipients[0]}{log.recipients.length > 1 ? ` 외 ${log.recipients.length - 1}명` : ''}</span></td>
              <td><span class:status-ok={log.status === 'accepted'} class:status-warn={log.status === 'pending' || log.status === 'unknown'} class:status-off={log.status === 'failed'} class="status-pill">{statusLabel[log.status]}</span></td>
              <td class="error-cell">{log.error_code ? `${log.error_code} · ` : ''}{log.error_message ?? '—'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <div class="pagination">
      <span class="muted small">{logs.total.toLocaleString()}건 중 {logs.offset + 1}–{Math.min(logs.offset + logs.items.length, logs.total)}</span>
      <div class="button-row"><button class="secondary" type="button" disabled={logs.offset === 0} on:click={() => load(Math.max(0, logs.offset - limit))}>이전</button><button class="secondary" type="button" disabled={logs.offset + logs.items.length >= logs.total} on:click={() => load(logs.offset + limit)}>다음</button></div>
    </div>
  {/if}
</section>
