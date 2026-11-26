# Imagem oficial do Playwright: Chromium + dependências de sistema já instalados.
# A versão da imagem PRECISA bater com a do pacote playwright no uv.lock.
FROM mcr.microsoft.com/playwright/python:v1.62.0-noble
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /usr/local/bin/uv
WORKDIR /srv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY app ./app
RUN uv sync --frozen --no-dev && chown -R pwuser:pwuser /srv
USER pwuser
ENV HOME=/tmp
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD ["/srv/.venv/bin/python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status==200 else 1)"]
CMD ["/srv/.venv/bin/uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--ws-max-size", "1048576"]
