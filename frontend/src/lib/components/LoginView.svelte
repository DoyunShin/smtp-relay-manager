<script lang="ts">
  import { acceptInvitation, errorMessage, login } from '$lib/api';
  import type { SessionData } from '$lib/types';
  import Notice from './Notice.svelte';

  export let invitationToken: string | null = null;
  export let onAuthenticated: (session: SessionData) => void;

  let username = '';
  let password = '';
  let passwordConfirm = '';
  let loading = false;
  let error = '';

  async function submit(): Promise<void> {
    error = '';
    if (invitationToken && password !== passwordConfirm) {
      error = '비밀번호가 서로 일치하지 않습니다.';
      return;
    }
    loading = true;
    try {
      const session = invitationToken
        ? await acceptInvitation(invitationToken, password)
        : await login(username.trim(), password);
      onAuthenticated(session);
      history.replaceState({}, '', '/');
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      loading = false;
    }
  }
</script>

<svelte:head>
  <title>{invitationToken ? '초대 수락' : '로그인'} | SMTP Relay Manager</title>
</svelte:head>

<main class="auth-page">
  <section class="auth-card" aria-labelledby="auth-title">
    <div class="brand-mark" aria-hidden="true">SR</div>
    <p class="eyebrow">SMTP RELAY MANAGER</p>
    <h1 id="auth-title">{invitationToken ? '계정을 시작하세요' : '관리 콘솔 로그인'}</h1>
    <p class="muted">
      {invitationToken
        ? '초대받은 계정에서 사용할 비밀번호를 설정합니다.'
        : '도메인과 발신 권한을 안전하게 관리합니다.'}
    </p>

    <Notice kind="error" message={error} />

    <form on:submit|preventDefault={submit}>
      {#if !invitationToken}
        <label>
          사용자 이름
          <input bind:value={username} autocomplete="username" required />
        </label>
      {/if}
      <label>
        {invitationToken ? '새 비밀번호' : '비밀번호'}
        <input
          type="password"
          bind:value={password}
          autocomplete={invitationToken ? 'new-password' : 'current-password'}
          minlength="12"
          required
        />
      </label>
      {#if invitationToken}
        <label>
          비밀번호 확인
          <input type="password" bind:value={passwordConfirm} autocomplete="new-password" minlength="12" required />
        </label>
      {/if}
      <button class="primary full" type="submit" disabled={loading}>
        {loading ? '처리 중…' : invitationToken ? '초대 수락' : '로그인'}
      </button>
    </form>
  </section>
</main>
