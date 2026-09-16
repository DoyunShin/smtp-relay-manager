import { expect, test, type Page, type Route } from '@playwright/test';

const user = {
  id: 'user-1',
  username: 'owner',
  active: true,
  is_operator: false,
  created_at: '2026-01-01T00:00:00Z'
};

const domain = {
  id: 'domain-1',
  name: 'example.com',
  status: 'approved',
  owner_user_id: user.id,
  owner_username: user.username,
  created_at: '2026-01-02T00:00:00Z'
};

function envelope(data: unknown, status = 200, message = 'ok') {
  return { status, message, data };
}

async function json(route: Route, data: unknown, status = 200): Promise<void> {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(envelope(data, status)) });
}

async function mockAuthenticated(page: Page): Promise<void> {
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith('/auth/me')) return json(route, { user, csrf_token: 'csrf-test' });
    if (url.pathname.endsWith('/domains')) return json(route, [domain]);
    if (url.pathname.endsWith(`/domains/${domain.id}`)) {
      return json(route, {
        domain,
        role: 'owner',
        smtp_config: {
          domain_id: domain.id,
          host: 'smtp.provider.test',
          port: 587,
          security: 'starttls',
          auth_type: 'password',
          username: 'relay-user',
          password_set: true
        },
        addresses: [{ id: 'address-1', domain_id: domain.id, address: 'notice@example.com' }],
        admins: [],
        grants: []
      });
    }
    if (url.pathname.endsWith(`/domains/${domain.id}/grants`)) return json(route, []);
    return json(route, null, 404);
  });
}

test('logs in, keeps the CSRF token, and submits a domain request', async ({ page }) => {
  let csrfHeader = '';
  let submittedName = '';

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname.endsWith('/auth/me')) return json(route, null, 401);
    if (url.pathname.endsWith('/auth/login')) {
      expect(request.postDataJSON()).toEqual({ username: 'owner', password: 'correct-password' });
      return json(route, { user, csrf_token: 'csrf-after-login' });
    }
    if (url.pathname.endsWith('/domains') && request.method() === 'GET') return json(route, []);
    if (url.pathname.endsWith('/domains') && request.method() === 'POST') {
      csrfHeader = request.headers()['x-csrf-token'] ?? '';
      submittedName = request.postDataJSON().name;
      return json(route, { ...domain, name: submittedName, status: 'pending' });
    }
    return json(route, null, 404);
  });

  await page.goto('/');
  await page.getByLabel('사용자 이름').fill('owner');
  await page.getByLabel('비밀번호').fill('correct-password');
  await page.getByRole('button', { name: '로그인' }).click();
  await expect(page.getByRole('heading', { name: '도메인', exact: true })).toBeVisible();

  await page.getByLabel('도메인 이름').fill('New-Relay.Example');
  await page.getByRole('button', { name: '등록 신청' }).click();
  await expect(page.getByText('도메인 등록을 신청했습니다')).toBeVisible();
  expect(csrfHeader).toBe('csrf-after-login');
  expect(submittedName).toBe('new-relay.example');
});

test('shows owner-only SMTP controls and blocks password auth on plaintext transport', async ({ page }) => {
  await mockAuthenticated(page);
  await page.goto('/');
  await page.getByRole('button', { name: '관리' }).click();

  await expect(page.getByRole('heading', { name: '외부 SMTP 서버' })).toBeVisible();
  await expect(page.getByLabel('서버 주소')).toHaveValue('smtp.provider.test');
  await page.getByLabel('연결 보안').selectOption('none');
  await expect(page.getByLabel('인증 방식')).toHaveValue('none');
  await expect(page.getByLabel('인증 방식').locator('option[value="password"]')).toHaveAttribute('disabled', '');
  await expect(page.getByRole('heading', { name: '발신 권한' })).toBeVisible();
  await expect(page.getByRole('heading', { name: '도메인 관리자' })).toBeVisible();
  await page.screenshot({ path: 'test-results/management-ui.png', fullPage: true });
});

test('accepts an invitation from the static fallback route', async ({ page }) => {
  let accepted = false;
  await page.route('**/api/v1/auth/invitations/accept', async (route) => {
    accepted = true;
    expect(route.request().postDataJSON()).toEqual({ token: 'invite-token', password: 'new-password' });
    await json(route, { user, csrf_token: 'csrf-invite' });
  });
  await page.route('**/api/v1/domains', (route) => json(route, []));

  await page.goto('/invite#token=invite-token');
  await expect(page).toHaveURL('/invite');
  await page.getByLabel('새 비밀번호').fill('new-password');
  await page.getByLabel('비밀번호 확인').fill('different-password');
  await page.getByRole('button', { name: '초대 수락' }).click();
  await expect(page.getByText('비밀번호가 서로 일치하지 않습니다.')).toBeVisible();
  expect(accepted).toBe(false);

  await page.getByLabel('비밀번호 확인').fill('new-password');
  await page.getByRole('button', { name: '초대 수락' }).click();
  await expect(page.getByRole('heading', { name: '도메인', exact: true })).toBeVisible();
  expect(accepted).toBe(true);
});

test('does not grant domain owner controls to a service operator', async ({ page }) => {
  const operator = { ...user, id: 'operator-1', username: 'operator', is_operator: true };
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith('/auth/me')) return json(route, { user: operator, csrf_token: 'csrf-operator' });
    if (url.pathname.endsWith('/domains')) return json(route, [domain]);
    if (url.pathname.endsWith(`/domains/${domain.id}`)) {
      return json(route, { domain, role: null, smtp_config: null, addresses: [], admins: [], grants: [] });
    }
    return json(route, null, 404);
  });

  await page.goto('/');
  await page.getByRole('button', { name: '관리' }).click();
  await expect(page.getByText('도메인 관리 역할: 없음')).toBeVisible();
  await expect(page.getByRole('heading', { name: '외부 SMTP 서버' })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: '발신 권한' })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: '도메인 관리자' })).toHaveCount(0);
});
