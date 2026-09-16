<script lang="ts">
  import { api, errorMessage } from '$lib/api';
  import { formatDateTime } from '$lib/time';
  import type { CreatedCredential, Credential, Domain, Scope } from '$lib/types';
  import Notice from './Notice.svelte';

  let credentials: Credential[] = [];
  let domains: Domain[] = [];
  let name = '';
  let expiresAt = '';
  let scopes: Scope[] = [{ domain_id: '', address: '*' }];
  let revealed: CreatedCredential | null = null;
  let editingId: string | null = null;
  let editScopes: Scope[] = [];
  let loading = true;
  let busy = false;
  let error = '';
  let success = '';
  let copied = '';

  async function load(): Promise<void> {
    loading = true;
    error = '';
    try {
      [credentials, domains] = await Promise.all([
        api<Credential[]>('/smtp-credentials'),
        api<Domain[]>('/domains')
      ]);
      if (domains.length && !scopes[0].domain_id) scopes[0].domain_id = domains[0].id;
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      loading = false;
    }
  }

  function addScope(target: 'create' | 'edit'): void {
    const next = { domain_id: domains[0]?.id ?? '', address: '*' };
    if (target === 'create') scopes = [...scopes, next];
    else editScopes = [...editScopes, next];
  }

  function removeScope(target: 'create' | 'edit', index: number): void {
    if (target === 'create') scopes = scopes.filter((_, current) => current !== index);
    else editScopes = editScopes.filter((_, current) => current !== index);
  }

  async function createCredential(): Promise<void> {
    busy = true;
    error = '';
    success = '';
    try {
      revealed = await api<CreatedCredential>('/smtp-credentials', {
        method: 'POST',
        body: JSON.stringify({
          name: name.trim(),
          scopes: scopes.map((scope) => ({ ...scope, address: scope.address.trim().toLowerCase() })),
          expires_at: expiresAt ? new Date(expiresAt).toISOString() : null
        })
      });
      credentials = [revealed.credential, ...credentials];
      name = '';
      expiresAt = '';
      scopes = [{ domain_id: domains[0]?.id ?? '', address: '*' }];
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  function startEditing(credential: Credential): void {
    editingId = credential.id;
    editScopes = credential.scopes.map((scope) => ({ ...scope }));
    if (!editScopes.length) addScope('edit');
  }

  async function saveScopes(): Promise<void> {
    if (!editingId) return;
    busy = true;
    error = '';
    try {
      const updated = await api<Credential>(`/smtp-credentials/${editingId}/scopes`, {
        method: 'PUT',
        body: JSON.stringify({ scopes: editScopes.map((scope) => ({ ...scope, address: scope.address.trim().toLowerCase() })) })
      });
      credentials = credentials.map((item) => (item.id === updated.id ? updated : item));
      editingId = null;
      success = '토큰의 발신 범위를 변경했습니다.';
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function revoke(credential: Credential): Promise<void> {
    if (!confirm(`‘${credential.name}’ 토큰을 폐기할까요?`)) return;
    busy = true;
    error = '';
    try {
      const updated = await api<Credential>(`/smtp-credentials/${credential.id}/revoke`, { method: 'POST' });
      credentials = credentials.map((item) => (item.id === updated.id ? updated : item));
      success = '토큰을 폐기했습니다.';
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function copy(label: string, value: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      copied = label;
      setTimeout(() => (copied = ''), 1600);
    } catch {
      error = '클립보드에 복사하지 못했습니다. 값을 직접 선택해 주세요.';
    }
  }

  function domainName(id: string): string {
    return domains.find((domain) => domain.id === id)?.name ?? id;
  }

  load();
</script>

<svelte:head><title>SMTP 토큰 | SMTP Relay Manager</title></svelte:head>

<div class="page-heading">
  <div>
    <p class="eyebrow">CREDENTIALS</p>
    <h1>SMTP 토큰</h1>
    <p class="muted">앱마다 별도 토큰을 발급하고 사용할 발신 범위를 제한합니다.</p>
  </div>
</div>

<Notice kind="error" message={error} />
<Notice kind="success" message={success} />

{#if revealed}
  <section class="secret-card" aria-labelledby="secret-title">
    <div class="section-heading">
      <div><h2 id="secret-title">발급된 SMTP 로그인 정보</h2><p>이 토큰은 지금만 확인할 수 있습니다. 안전한 곳에 저장하세요.</p></div>
      <button class="text-button" type="button" on:click={() => (revealed = null)}>확인 완료</button>
    </div>
    <div class="secret-row"><span>SMTP username</span><code>{revealed.username}</code><button class="secondary" type="button" on:click={() => copy('아이디', revealed!.username)}>{copied === '아이디' ? '복사됨' : '복사'}</button></div>
    <div class="secret-row"><span>SMTP password</span><code>{revealed.token}</code><button class="secondary" type="button" on:click={() => copy('토큰', revealed!.token)}>{copied === '토큰' ? '복사됨' : '복사'}</button></div>
  </section>
{/if}

<section class="panel" aria-labelledby="create-token-title">
  <h2 id="create-token-title">새 토큰 발급</h2>
  {#if domains.length === 0 && !loading}
    <p class="muted">먼저 발신 권한이 있는 도메인을 준비해 주세요.</p>
  {:else}
    <form class="stack-form" on:submit|preventDefault={createCredential}>
      <div class="form-grid">
        <label>토큰 이름<input bind:value={name} placeholder="production-app" required /></label>
        <label>만료 시각 (선택)<input type="datetime-local" bind:value={expiresAt} /></label>
      </div>
      <fieldset>
        <legend>발신 범위</legend>
        <p class="muted small">현재 사용자 권한과 여기서 지정한 범위가 모두 허용하는 주소만 사용할 수 있습니다.</p>
        {#each scopes as scope, index}
          <div class="scope-row">
            <label>도메인<select bind:value={scope.domain_id} required>{#each domains as domain}<option value={domain.id}>{domain.name}</option>{/each}</select></label>
            <label>주소<input bind:value={scope.address} placeholder="notice@example.com 또는 *" required /></label>
            <button class="danger-text scope-remove" type="button" on:click={() => removeScope('create', index)} disabled={scopes.length === 1}>제거</button>
          </div>
        {/each}
        <button class="secondary" type="button" on:click={() => addScope('create')}>범위 추가</button>
      </fieldset>
      <button class="primary align-start" type="submit" disabled={busy || domains.length === 0}>토큰 발급</button>
    </form>
  {/if}
</section>

<section class="panel" aria-labelledby="tokens-title">
  <h2 id="tokens-title">발급된 토큰</h2>
  {#if loading}
    <p class="muted">토큰을 불러오는 중입니다.</p>
  {:else}
    <div class="credential-list">
      {#each credentials as credential}
        <article class:disabled-card={credential.revoked_at} class="credential-card">
          <div class="section-heading">
            <div>
              <h3>{credential.name}</h3>
              <p class="muted small">발급 {formatDateTime(credential.created_at)}</p>
            </div>
            <span class:status-off={credential.revoked_at} class:status-ok={!credential.revoked_at} class="status-pill">{credential.revoked_at ? '폐기됨' : '사용 가능'}</span>
          </div>
          {#if editingId === credential.id}
            <form class="stack-form inset-form" on:submit|preventDefault={saveScopes}>
              {#each editScopes as scope, index}
                <div class="scope-row">
                  <label>도메인<select bind:value={scope.domain_id}>{#each domains as domain}<option value={domain.id}>{domain.name}</option>{/each}</select></label>
                  <label>주소<input bind:value={scope.address} required /></label>
                  <button class="danger-text scope-remove" type="button" on:click={() => removeScope('edit', index)} disabled={editScopes.length === 1}>제거</button>
                </div>
              {/each}
              <div class="button-row"><button class="secondary" type="button" on:click={() => addScope('edit')}>범위 추가</button><button class="primary" type="submit" disabled={busy}>저장</button><button class="text-button" type="button" on:click={() => (editingId = null)}>취소</button></div>
            </form>
          {:else}
            <ul class="scope-list">
              {#each credential.scopes as scope}<li><span>{domainName(scope.domain_id)}</span><code>{scope.address === '*' ? '전체 주소' : scope.address}</code></li>{/each}
            </ul>
            <p class="muted small">만료: {credential.expires_at ? formatDateTime(credential.expires_at) : '없음'}</p>
            {#if !credential.revoked_at}
              <div class="button-row"><button class="secondary" type="button" on:click={() => startEditing(credential)}>범위 변경</button><button class="danger-text" type="button" on:click={() => revoke(credential)}>폐기</button></div>
            {/if}
          {/if}
        </article>
      {:else}<p class="muted">발급된 토큰이 없습니다.</p>{/each}
    </div>
  {/if}
</section>
