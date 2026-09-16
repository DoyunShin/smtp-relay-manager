FROM ghcr.io/astral-sh/uv:0.11.4 AS uv
FROM python:3.12-slim
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY alembic ./alembic
COPY alembic.ini ./
RUN uv sync --frozen --no-dev && groupadd --gid 10001 relay && useradd --uid 10001 --gid relay --no-create-home relay
USER 10001:10001
EXPOSE 8000 8465 8587
CMD ["uvicorn", "smtp_relay_manager.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
