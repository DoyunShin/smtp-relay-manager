<script lang="ts">
  import { api, errorMessage } from '$lib/api';
  import type { DomainDetail, Grant, SmtpAuthType, SmtpConfig, SmtpSecurity } from '$lib/types';
  import Notice from './Notice.svelte';

  export let domainId: string;
  export let currentUsername: string;
  export let onBack: () => void;

  let detail: DomainDetail | null = null;
  let grants: Grant[] = [];
  let loading = true;
  let busy = false;
  let error = '';
  let success = '';

  let smtpHost = '';
  let smtpPort = 587;
  let smtpSecurity: SmtpSecurity = 'starttls';
  let smtpAuth: SmtpAuthType = 'none';
  let smtpUsername = '';
  let smtpPassword = '';

  let adminUsername = '';
  let ownerUsername = '';
  let address = '';
  let grantUsername = '';
  let grantAddress = '*';
  let deleteConfirm = '';

  $: isOwner = detail?.role === 'owner';
  $: canManageSenders = detail?.role === 'owner' || detail?.role === 'admin';
  $: ownGrants = detail?.grants.filter((grant) => grant.username === currentUsername) ?? [];
  $: if (smtpSecurity === 'none' && smtpAuth === 'password') smtpAuth = 'none';

  function fillSmtp(config: SmtpConfig | null): void {
    if (!config) return;
    smtpHost = config.host;
    smtpPort = config.port;
    smtpSecurity = config.security;
    smtpAuth = config.auth_type;
    smtpUsername = config.username ?? '';
  }

  async function load(): Promise<void> {
    loading = true;
    error = '';
    try {
      detail = await api<DomainDetail>(`/domains/${domainId}`);
      fillSmtp(detail.smtp_config);
      ownerUsername = detail.domain.owner_username;
      grants = detail.grants;
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      loading = false;
    }
  }

  function beginAction(): void {
    busy = true;
    error = '';
    success = '';
  }

  async function saveSmtp(): Promise<void> {
    beginAction();
    try {
      const payload = {
        host: smtpHost.trim(),
        port: Number(smtpPort),
        security: smtpSecurity,
        auth_type: smtpAuth,
        username: smtpAuth === 'password' ? smtpUsername.trim() : null,
        password: smtpAuth === 'password' && smtpPassword ? smtpPassword : undefined
      };
      const config = await api<SmtpConfig>(`/domains/${domainId}/smtp`, {
        method: 'PUT',
        body: JSON.stringify(payload)
      });
      if (detail) detail = { ...detail, smtp_config: config };
      smtpPassword = '';
      fillSmtp(config);
      success = '외부 SMTP 설정을 저장했습니다.';
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function addAdmin(): Promise<void> {
    beginAction();
    try {
      await api<unknown>(`/domains/${domainId}/admins/${encodeURIComponent(adminUsername.trim())}`, { method: 'PUT' });
      adminUsername = '';
      await load();
      success = '관리자를 지정했습니다.';
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function removeAdmin(username: string): Promise<void> {
    beginAction();
    try {
      await api<unknown>(`/domains/${domainId}/admins/${encodeURIComponent(username)}`, { method: 'DELETE' });
      if (detail) detail = { ...detail, admins: detail.admins.filter((item) => item.username !== username) };
      success = '관리자 권한을 해제했습니다.';
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function transferOwner(): Promise<void> {
    if (!confirm(`${ownerUsername} 사용자에게 소유권을 이전할까요?`)) return;
    beginAction();
    try {
      await api<unknown>(`/domains/${domainId}/owner`, {
        method: 'PUT',
        body: JSON.stringify({ username: ownerUsername.trim() })
      });
      onBack();
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function deleteDomain(): Promise<void> {
    if (!detail || deleteConfirm !== detail.domain.name) {
      error = '삭제하려면 도메인 이름을 정확히 입력해 주세요.';
      return;
    }
    beginAction();
    try {
      await api<unknown>(`/domains/${domainId}`, { method: 'DELETE' });
      onBack();
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function addAddress(): Promise<void> {
    beginAction();
    try {
      await api<unknown>(`/domains/${domainId}/addresses`, {
        method: 'POST',
        body: JSON.stringify({ address: address.trim().toLowerCase() })
      });
      address = '';
      await load();
      success = '발신 주소를 추가했습니다.';
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function removeAddress(id: string): Promise<void> {
    beginAction();
    try {
      await api<unknown>(`/domains/${domainId}/addresses/${id}`, { method: 'DELETE' });
      if (detail) detail = { ...detail, addresses: detail.addresses.filter((item) => item.id !== id) };
      grants = grants.filter((item) => item.address === '*' || detail?.addresses.some((a) => a.address === item.address));
      success = '발신 주소를 삭제했습니다.';
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function addGrant(): Promise<void> {
    beginAction();
    try {
      const created = await api<Grant>(`/domains/${domainId}/grants`, {
        method: 'POST',
        body: JSON.stringify({ username: grantUsername.trim(), address: grantAddress })
      });
      grants = [...grants, created];
      if (detail) detail = { ...detail, grants: [...detail.grants, created] };
      grantUsername = '';
      success = '발신 권한을 할당했습니다.';
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function removeGrant(id: string): Promise<void> {
    beginAction();
    try {
      await api<unknown>(`/domains/${domainId}/grants/${id}`, { method: 'DELETE' });
      grants = grants.filter((item) => item.id !== id);
      if (detail) detail = { ...detail, grants: detail.grants.filter((item) => item.id !== id) };
      success = '발신 권한을 회수했습니다.';
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  load();
</script>

<button class="back-link" type="button" on:click={onBack}>← 도메인 목록</button>

{#if loading}
  <div class="empty-state">도메인 정보를 불러오는 중입니다.</div>
{:else if detail}
  <div class="page-heading">
    <div>
      <p class="eyebrow">DOMAIN</p>
      <h1>{detail.domain.name}</h1>
      <p class="muted">도메인 관리 역할: {detail.role === 'owner' ? '소유자' : detail.role === 'admin' ? '관리자' : '없음'}</p>
    </div>
    <span class:status-ok={detail.domain.status === 'approved'} class:status-warn={detail.domain.status === 'pending'} class:status-off={detail.domain.status === 'rejected'} class="status-pill">
      {detail.domain.status === 'approved' ? '사용 중' : detail.domain.status === 'pending' ? '승인 대기' : '반려됨'}
    </span>
  </div>

  <Notice kind="error" message={error} />
  <Notice kind="success" message={success} />

  <section class="panel compact-panel" aria-labelledby="my-sender-access">
    <div>
      <h2 id="my-sender-access">내 발신 범위</h2>
      <p class="muted small">도메인 역할만으로는 발송 권한이 생기지 않습니다.</p>
    </div>
    <div class="button-row">
      {#each ownGrants as grant}<code>{grant.address === '*' ? '도메인 전체' : grant.address}</code>{:else}<span class="muted small">할당된 발신 주소 없음</span>{/each}
    </div>
  </section>

  {#if isOwner}
    <section class="panel" aria-labelledby="smtp-settings">
      <div class="section-heading">
        <div>
          <h2 id="smtp-settings">외부 SMTP 서버</h2>
          <p class="muted small">이 도메인의 메일이 최종 전달될 서버입니다.</p>
        </div>
        {#if detail.smtp_config?.password_set}<span class="status-pill status-ok">비밀번호 저장됨</span>{/if}
      </div>
      <form class="form-grid" on:submit|preventDefault={saveSmtp}>
        <label class="span-2">서버 주소<input bind:value={smtpHost} placeholder="smtp.provider.com" required /></label>
        <label>포트<input type="number" bind:value={smtpPort} min="1" max="65535" required /></label>
        <label>연결 보안
          <select bind:value={smtpSecurity}>
            <option value="none">암호화 없음</option>
            <option value="starttls">STARTTLS</option>
            <option value="tls">TLS</option>
          </select>
        </label>
        <label>인증 방식
          <select bind:value={smtpAuth}>
            <option value="none">인증 없음</option>
            <option value="password" disabled={smtpSecurity === 'none'}>아이디 / 비밀번호</option>
          </select>
        </label>
        {#if smtpAuth === 'password'}
          <label>SMTP 아이디<input bind:value={smtpUsername} autocomplete="off" required /></label>
          <label>SMTP 비밀번호
            <input type="password" bind:value={smtpPassword} autocomplete="new-password" placeholder={detail.smtp_config?.password_set ? '변경할 때만 입력' : ''} required={!detail.smtp_config?.password_set} />
          </label>
        {/if}
        <div class="form-actions span-all"><button class="primary" type="submit" disabled={busy}>설정 저장</button></div>
      </form>
    </section>
  {/if}

  {#if canManageSenders}
    <div class="two-column">
      <section class="panel" aria-labelledby="addresses-title">
        <h2 id="addresses-title">발신 주소</h2>
        <form class="inline-form" on:submit|preventDefault={addAddress}>
          <label class="sr-only" for="new-address">발신 주소</label>
          <input id="new-address" type="email" bind:value={address} placeholder={`notice@${detail.domain.name}`} required />
          <button class="primary" type="submit" disabled={busy}>추가</button>
        </form>
        <ul class="item-list">
          {#each detail.addresses as item}
            <li><code>{item.address}</code><button class="danger-text" type="button" on:click={() => removeAddress(item.id)}>삭제</button></li>
          {:else}<li class="muted">등록된 주소가 없습니다.</li>{/each}
        </ul>
      </section>

      <section class="panel" aria-labelledby="grants-title">
        <h2 id="grants-title">발신 권한</h2>
        <form class="stack-form" on:submit|preventDefault={addGrant}>
          <label>사용자 이름<input bind:value={grantUsername} placeholder="기존 사용자 이름" required /></label>
          <label>허용 주소
            <select bind:value={grantAddress}>
              <option value="*">도메인 전체 (*)</option>
              {#each detail.addresses as item}<option value={item.address}>{item.address}</option>{/each}
            </select>
          </label>
          <button class="primary align-start" type="submit" disabled={busy}>권한 할당</button>
        </form>
        <ul class="item-list">
          {#each grants as grant}
            <li><span><strong>{grant.username}</strong><small>{grant.address === '*' ? '도메인 전체' : grant.address}</small></span><button class="danger-text" type="button" on:click={() => removeGrant(grant.id)}>회수</button></li>
          {:else}<li class="muted">할당된 발신 권한이 없습니다.</li>{/each}
        </ul>
      </section>
    </div>
  {/if}

  {#if isOwner}
    <section class="panel" aria-labelledby="admins-title">
      <h2 id="admins-title">도메인 관리자</h2>
      <form class="inline-form" on:submit|preventDefault={addAdmin}>
        <label class="sr-only" for="admin-name">사용자 이름</label>
        <input id="admin-name" bind:value={adminUsername} placeholder="기존 사용자 이름" required />
        <button class="primary" type="submit" disabled={busy}>관리자 지정</button>
      </form>
      <ul class="item-list">
        {#each detail.admins as admin}
          <li><span><strong>{admin.username}</strong><small>{admin.active ? '활성' : '비활성'}</small></span><button class="danger-text" type="button" on:click={() => removeAdmin(admin.username)}>해제</button></li>
        {:else}<li class="muted">지정된 관리자가 없습니다.</li>{/each}
      </ul>
    </section>

    <section class="panel danger-zone" aria-labelledby="ownership-title">
      <h2 id="ownership-title">소유권 및 삭제</h2>
      <div class="danger-actions">
        <form class="inline-form" on:submit|preventDefault={transferOwner}>
          <label class="sr-only" for="owner-name">새 소유자</label>
          <input id="owner-name" bind:value={ownerUsername} placeholder="새 소유자 이름" required />
          <button class="secondary" type="submit" disabled={busy || ownerUsername === detail.domain.owner_username}>소유권 이전</button>
        </form>
        <form class="inline-form" on:submit|preventDefault={deleteDomain}>
          <label class="sr-only" for="delete-confirm">도메인 이름 확인</label>
          <input id="delete-confirm" bind:value={deleteConfirm} placeholder={detail.domain.name} required />
          <button class="danger" type="submit" disabled={busy}>도메인 삭제</button>
        </form>
      </div>
      <p class="muted small">삭제 확인란에는 <code>{detail.domain.name}</code>을 입력하세요.</p>
    </section>
  {/if}
{:else}
  <Notice kind="error" message={error || '도메인 정보를 찾을 수 없습니다.'} />
{/if}
