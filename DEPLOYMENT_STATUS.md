# Estado da publicação

**Estado: aplicação preparada localmente, mas ainda não publicada na internet.**

## O que foi corrigido e validado

- O seed tem 2.594 perguntas: A 298, B 1.962, C 157 e D 177; 2.413 perguntas têm uma imagem associada.
- O seed foi limpo de contas e histórico. A base local com contas foi preservada e não foi usada nos testes.
- O login de administrador exige MFA TOTP em desenvolvimento e produção; já não cria uma sessão antes da confirmação do segundo fator.
- A interface inclui configuração inicial TOTP, confirmação do código e entrada de código de autenticação/recuperação.
- A regra de tema escuro foi corrigida; o controlo de tema está disponível na página pública e na área autenticada.
- A navegação lateral em ecrãs pequenos foi ajustada para abrir como menu.
- Foi acrescentada a dependência python-multipart exigida pela rota de carregamento de imagens.
- A suíte de API executada em base temporária terminou com 7 testes aprovados; inclui registo, login, MFA, revogação, recuperação, teste B e recursos frontend. Há um aviso de depreciação do TestClient (httpx/Starlette), sem falhas de teste.

## Verificações ainda por fazer

- Rever visualmente em Chrome e Firefox e em vários tamanhos de ecrã; a ferramenta de controlo do browser não conseguiu aceder à janela atual nesta sessão.
- Testar em profundidade os formatos A/C/D, filtros por tema, modo claro/escuro e fluxos completos em browser.
- Validar envio real de recuperação de password com SMTP.

## Necessário para publicar

- Servidor Docker Compose e acesso SSH.
- Domínio/subdomínio apontado por DNS para o servidor e portas 80/443 acessíveis.
- Valores reais para SESSION_SECRET, CAT_ADMIN_PASSWORD e serviço SMTP.
- Configurar o domínio no Caddyfile e em CORS_ORIGINS.
- MFA TOTP do administrador tem de ser configurado antes da utilização do painel.

Não foi criada URL pública. A publicação só pode ser concluída depois de existirem servidor, domínio, DNS e SMTP.



