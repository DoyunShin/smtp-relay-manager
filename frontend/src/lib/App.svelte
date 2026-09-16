<script lang="ts">
  import { onMount } from 'svelte';
  import { ApiError, errorMessage, loadSession, logout } from '$lib/api';
  import type { SessionData } from '$lib/types';
  import CredentialsView from './components/CredentialsView.svelte';
  import DomainDetailView from './components/DomainDetailView.svelte';
  import DomainsView from './components/DomainsView.svelte';
  import LoginView from './components/LoginView.svelte';
  import LogsView from './components/LogsView.svelte';
  import Notice from './components/Notice.svelte';
  import OperatorView from './components/OperatorView.svelte';
  import './styles.css';

  type View = 'domains' | 'credentials' | 'logs' | 'users';

  let session: SessionData | null = null;
  let loading = true;
  let startupError = '';
  let view: View = 'domains';
  let selectedDomainId: string | null = null;
  let menuOpen = false;

  const invitationPage = location.pathname.replace(/\/$/, '') === '/invite';
  const invitationToken = invitationPage
    ? new URLSearchParams(location.hash.slice(1)).get('token')
    : null;
  if (invitationToken) history.replaceState({}, '', '/invite');

  onMount(async () => {
    if (invitationToken) {
      loading = false;
      return;
    }
    try {
      session = await loadSession();
    } catch (caught) {
      if (!(caught instanceof ApiError) || caught.status !== 401) startupError = errorMessage(caught);
    } finally {
      loading = false;
    }
  });

  function authenticate(data: SessionData): void {
    session = data;
    startupError = '';
    view = 'domains';
    selectedDomainId = null;
  }

  function selectView(next: View): void {
    view = next;
    selectedDomainId = null;
    menuOpen = false;
  }

  async function signOut(): Promise<void> {
    try {
      await logout();
    } catch {
      // Clear the local session even if the server session already expired.
    }
    session = null;
    view = 'domains';
    selectedDomainId = null;
  }
</script>

{#if loading}
  <main class="loading-page"><div class="brand-mark">SR</div><p>관리 콘솔을 불러오는 중입니다.</p></main>
{:else if !session}
  {#if startupError}<div class="startup-notice"><Notice kind="error" message={startupError} /></div>{/if}
  <LoginView {invitationToken} onAuthenticated={authenticate} />
{:else}
  <div class="app-shell">
    <aside class:menu-open={menuOpen} class="sidebar">
      <div class="sidebar-brand"><div class="brand-mark small-mark">SR</div><div><strong>SMTP Relay</strong><span>Manager</span></div></div>
      <nav aria-label="주 메뉴">
        <button class:active={view === 'domains'} type="button" on:click={() => selectView('domains')}><span aria-hidden="true">D</span>도메인</button>
        <button class:active={view === 'credentials'} type="button" on:click={() => selectView('credentials')}><span aria-hidden="true">K</span>SMTP 토큰</button>
        <button class:active={view === 'logs'} type="button" on:click={() => selectView('logs')}><span aria-hidden="true">L</span>발송 기록</button>
        {#if session.user.is_operator}
          <p class="nav-label">운영</p>
          <button class:active={view === 'users'} type="button" on:click={() => selectView('users')}><span aria-hidden="true">U</span>사용자 및 초대</button>
        {/if}
      </nav>
      <div class="sidebar-user"><div><strong>{session.user.username}</strong><span>{session.user.is_operator ? '서비스 운영자' : '사용자'}</span></div><button class="text-button light" type="button" on:click={signOut}>로그아웃</button></div>
    </aside>
    {#if menuOpen}<button class="menu-scrim" aria-label="메뉴 닫기" type="button" on:click={() => (menuOpen = false)}></button>{/if}

    <div class="main-column">
      <header class="mobile-header"><button class="menu-button" type="button" aria-label="메뉴 열기" on:click={() => (menuOpen = true)}>☰</button><strong>SMTP Relay Manager</strong></header>
      <main class="content">
        {#if selectedDomainId}
          <DomainDetailView domainId={selectedDomainId} currentUsername={session.user.username} onBack={() => (selectedDomainId = null)} />
        {:else if view === 'domains'}
          <DomainsView user={session.user} onSelect={(id) => (selectedDomainId = id)} />
        {:else if view === 'credentials'}
          <CredentialsView />
        {:else if view === 'logs'}
          <LogsView />
        {:else if view === 'users' && session.user.is_operator}
          <OperatorView />
        {/if}
      </main>
    </div>
  </div>
{/if}
