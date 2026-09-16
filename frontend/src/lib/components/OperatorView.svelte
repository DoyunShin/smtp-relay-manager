<script lang="ts">
  import { api, errorMessage } from '$lib/api';
  import { formatDate, formatDateTime } from '$lib/time';
  import type { CreatedUser, Invitation, OperatorUser, PageData, User } from '$lib/types';
  import Notice from './Notice.svelte';

  const limit = 50;
  let users: PageData<OperatorUser> = { items: [], total: 0, limit, offset: 0 };
  let username = '';
  let invitation: Invitation | null = null;
  let loading = true;
  let busy = false;
  let error = '';
  let success = '';
  let copied = false;

  async function load(offset = 0): Promise<void> {
    loading = true;
    error = '';
    try {
      users = await api<PageData<OperatorUser>>(`/users?limit=${limit}&offset=${offset}`);
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      loading = false;
    }
  }

  async function createUser(): Promise<void> {
    busy = true;
    error = '';
    invitation = null;
    try {
      const created = await api<CreatedUser>('/users', {
        method: 'POST',
        body: JSON.stringify({ username: username.trim() })
      });
      invitation = created.invitation;
      username = '';
      await load(users.offset);
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function setActive(user: OperatorUser): Promise<void> {
    busy = true;
    error = '';
    try {
      const updated = await api<User>(`/users/${user.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ active: !user.active })
      });
      users = { ...users, items: users.items.map((item) => (item.id === updated.id ? { ...item, ...updated } : item)) };
      success = updated.active ? '사용자를 활성화했습니다.' : '사용자를 비활성화했습니다.';
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function setOperator(user: OperatorUser): Promise<void> {
    if (!confirm(`${user.username} 사용자의 운영자 권한을 ${user.is_operator ? '해제' : '부여'}할까요?`)) return;
    busy = true;
    error = '';
    try {
      const updated = await api<User>(`/users/${user.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ is_operator: !user.is_operator })
      });
      users = { ...users, items: users.items.map((item) => (item.id === updated.id ? { ...item, ...updated } : item)) };
      success = updated.is_operator ? '운영자 권한을 부여했습니다.' : '운영자 권한을 해제했습니다.';
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function reissue(user: OperatorUser): Promise<void> {
    if (!user.invitation) return;
    busy = true;
    error = '';
    try {
      invitation = await api<Invitation>(`/invitations/${user.invitation.id}/reissue`, { method: 'POST' });
      await load(users.offset);
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function revokeInvitation(user: OperatorUser): Promise<void> {
    if (!user.invitation || !confirm(`${user.username} 사용자의 초대를 취소할까요?`)) return;
    busy = true;
    error = '';
    try {
      await api<unknown>(`/invitations/${user.invitation.id}`, { method: 'DELETE' });
      await load(users.offset);
      success = '초대를 취소했습니다.';
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  function invitationLink(value: Invitation): string {
    if (value.invitation_url) return value.invitation_url;
    return `${location.origin}/invite#token=${encodeURIComponent(value.token ?? '')}`;
  }

  async function copyInvitation(): Promise<void> {
    if (!invitation) return;
    try {
      await navigator.clipboard.writeText(invitationLink(invitation));
      copied = true;
      setTimeout(() => (copied = false), 1600);
    } catch {
      error = '초대 링크를 복사하지 못했습니다. 직접 선택해 주세요.';
    }
  }

  load();
</script>

<svelte:head><title>사용자 | SMTP Relay Manager</title></svelte:head>

<div class="page-heading">
  <div><p class="eyebrow">OPERATIONS</p><h1>사용자 및 초대</h1><p class="muted">서비스 사용자를 만들고 일회용 초대 링크를 관리합니다.</p></div>
</div>

<Notice kind="error" message={error} />
<Notice kind="success" message={success} />

{#if invitation}
  <section class="secret-card" aria-labelledby="invite-result-title">
    <div class="section-heading"><div><h2 id="invite-result-title">새 초대 링크</h2><p>링크는 안전한 채널로 사용자에게 전달하세요.</p></div><button class="text-button" type="button" on:click={() => (invitation = null)}>확인 완료</button></div>
    <div class="secret-row"><span>초대 링크</span><code>{invitationLink(invitation)}</code><button class="secondary" type="button" on:click={copyInvitation}>{copied ? '복사됨' : '복사'}</button></div>
    <p class="small">만료: {formatDateTime(invitation.expires_at)}</p>
  </section>
{/if}

<section class="panel compact-panel" aria-labelledby="create-user-title">
  <div><h2 id="create-user-title">사용자 초대</h2><p class="muted small">사용자를 만들면 한 번만 표시되는 초대 링크가 발급됩니다.</p></div>
  <form class="inline-form" on:submit|preventDefault={createUser}>
    <label class="sr-only" for="new-username">사용자 이름</label>
    <input id="new-username" bind:value={username} placeholder="사용자 이름" required />
    <button class="primary" type="submit" disabled={busy}>사용자 생성</button>
  </form>
</section>

<section class="panel table-panel" aria-label="사용자 목록">
  {#if loading}<div class="empty-state">사용자를 불러오는 중입니다.</div>
  {:else}
    <div class="table-scroll">
      <table>
        <thead><tr><th>사용자</th><th>구분</th><th>상태</th><th>가입</th><th>관리</th></tr></thead>
        <tbody>
          {#each users.items as user}
            <tr>
              <td><strong>{user.username}</strong></td>
              <td>{user.is_operator ? '운영자' : '일반 사용자'}</td>
              <td><span class:status-ok={user.active} class:status-off={!user.active} class="status-pill">{user.active ? '활성' : '비활성'}</span></td>
              <td>{user.invitation && !user.invitation.used_at ? `초대 대기 · ${formatDate(user.invitation.expires_at)}` : formatDate(user.created_at)}</td>
              <td><div class="button-row"><button class="secondary" type="button" disabled={busy} on:click={() => setActive(user)}>{user.active ? '비활성화' : '활성화'}</button><button class="text-button" type="button" disabled={busy} on:click={() => setOperator(user)}>{user.is_operator ? '운영자 해제' : '운영자 지정'}</button>{#if user.invitation && !user.invitation.used_at}<button class="text-button" type="button" on:click={() => reissue(user)}>재발급</button><button class="danger-text" type="button" on:click={() => revokeInvitation(user)}>초대 취소</button>{/if}</div></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <div class="pagination"><span class="muted small">총 {users.total.toLocaleString()}명</span><div class="button-row"><button class="secondary" type="button" disabled={users.offset === 0} on:click={() => load(Math.max(0, users.offset - limit))}>이전</button><button class="secondary" type="button" disabled={users.offset + users.items.length >= users.total} on:click={() => load(users.offset + limit)}>다음</button></div></div>
  {/if}
</section>
