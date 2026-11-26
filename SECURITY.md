# Segurança

O QP existe para isolar páginas não confiáveis, então uma falha que fure esse
isolamento é tratada como prioridade.

## Como reportar

Use o reporte privado do GitHub: aba **Security** deste repositório →
**Report a vulnerability**. Não abra issue pública nem PR com o detalhe da falha.

Inclua, se puder: o modo afetado (isolado, renderizado ou remoto), a URL ou o HTML
que reproduz, o que deveria ter sido bloqueado e o que passou.

## O que conta como falha

- Script da página alvo executando no navegador de quem usa o QP (escape do
  sanitizador, do CSP ou do sandbox do iframe).
- O servidor alcançando endereço interno (SSRF): loopback, rede privada, metadata
  de nuvem, inclusive por redirect ou DNS rebinding.
- O Chromium do modo remoto saindo por fora do proxy de saída guardado.
- Contornar a senha (`SAFEBROWSE_AUTH_PASSWORD`) ou a checagem de `Origin` do portão.

Não contam: sites que não funcionam no modo isolado, captcha ou bloqueio por IP de
datacenter, e instalações expostas sem senha nem login na frente (o README avisa).
