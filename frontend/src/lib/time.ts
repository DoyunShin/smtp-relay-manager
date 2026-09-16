const TIMEZONE_SUFFIX = /(?:z|[+-]\d{2}:\d{2})$/i;

export function parseApiTimestamp(value: string): Date {
  return new Date(TIMEZONE_SUFFIX.test(value) ? value : `${value}Z`);
}

export function formatDate(value: string): string {
  return parseApiTimestamp(value).toLocaleDateString('ko-KR');
}

export function formatDateTime(value: string): string {
  return parseApiTimestamp(value).toLocaleString('ko-KR');
}
