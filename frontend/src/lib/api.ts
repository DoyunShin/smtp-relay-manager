import type { Envelope, SessionData } from './types';

const API_ROOT = '/api/v1';
let csrfToken = '';

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export function setCsrfToken(token: string): void {
  csrfToken = token;
}

export function clearCsrfToken(): void {
  csrfToken = '';
}

export async function api<T>(
  path: string,
  options: RequestInit & { public?: boolean } = {}
): Promise<T> {
  const { public: isPublic = false, ...requestOptions } = options;
  const method = (requestOptions.method ?? 'GET').toUpperCase();
  const headers = new Headers(requestOptions.headers);

  if (requestOptions.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (!isPublic && !['GET', 'HEAD', 'OPTIONS'].includes(method) && csrfToken) {
    headers.set('X-CSRF-Token', csrfToken);
  }

  let response: Response;
  try {
    response = await fetch(`${API_ROOT}${path}`, {
      ...requestOptions,
      method,
      headers,
      credentials: 'same-origin'
    });
  } catch {
    throw new ApiError(0, '서버에 연결할 수 없습니다. 잠시 후 다시 시도해 주세요.');
  }

  let envelope: Envelope<T> | null = null;
  try {
    envelope = (await response.json()) as Envelope<T>;
  } catch {
    if (!response.ok) {
      throw new ApiError(response.status, '요청을 처리하지 못했습니다.');
    }
  }

  if (!response.ok) {
    throw new ApiError(
      envelope?.status ?? response.status,
      envelope?.message || '요청을 처리하지 못했습니다.'
    );
  }
  if (!envelope) return undefined as T;
  return envelope.data as T;
}

export async function loadSession(): Promise<SessionData> {
  const session = await api<SessionData>('/auth/me');
  setCsrfToken(session.csrf_token);
  return session;
}

export async function login(username: string, password: string): Promise<SessionData> {
  const session = await api<SessionData>('/auth/login', {
    method: 'POST',
    public: true,
    body: JSON.stringify({ username, password })
  });
  setCsrfToken(session.csrf_token);
  return session;
}

export async function acceptInvitation(token: string, password: string): Promise<SessionData> {
  const session = await api<SessionData>('/auth/invitations/accept', {
    method: 'POST',
    public: true,
    body: JSON.stringify({ token, password })
  });
  setCsrfToken(session.csrf_token);
  return session;
}

export async function logout(): Promise<void> {
  await api<unknown>('/auth/logout', { method: 'POST' });
  clearCsrfToken();
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : '알 수 없는 오류가 발생했습니다.';
}
