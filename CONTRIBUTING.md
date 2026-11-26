# Contribuindo com o QP

Obrigado pelo interesse. Issues e pull requests são bem-vindos, em português ou inglês.

## Antes de abrir um PR

1. Para mudança grande (um modo novo, outra dependência, mudança no desenho de
   segurança), abra uma issue primeiro para combinar o caminho.
2. Descreva na issue ou no PR o que deve ser verdade quando a mudança estiver pronta,
   em itens que dê para conferir no diff.
3. Rode localmente:
   ```bash
   uv sync
   uv run ruff check app tests && uv run ruff format --check app tests
   uv run pytest -m "not remote"                # rápido, sem Chromium
   uv run playwright install chromium && uv run pytest   # suíte inteira
   ```
4. Mudança no sanitizador, no guard de URL ou no proxy de saída vem com teste do
   vetor que ela fecha (veja `tests/test_sanitizer_vectors.py`).

No PR, escreva `Fecha #N` para ligar a issue. O merge é por squash.

## Falhas de segurança

Não abra issue pública para falha de segurança. Siga o [SECURITY.md](SECURITY.md).
