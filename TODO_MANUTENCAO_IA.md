# Trabalho para concluir Carta Auto Testes

## Estado atual confirmado

- API FastAPI e interface JavaScript sem framework.
- Seed com 2.594 perguntas: A 298, B 1.962, C 157 e D 177; 2.413 têm imagem associada.
- A base de desenvolvimento carta_auto_testes.db contém contas e deve ser preservada, não enviada no pacote de transição nem usada em testes.
- seed/carta_auto_testes_seed.db foi deixado sem contas/histórico e é usado para publicação e testes isolados.
- Funcionalidades disponíveis: login/registo, licenças, categorias, exames, resultados/revisão, favoritos, histórico, estatísticas, administração de alunos/perguntas e upload de imagem.
- MFA TOTP obrigatório para todos os administradores, sem bypass em modo de desenvolvimento.
- Dependência python-multipart acrescentada para upload de imagens.
- Testes de API existentes: 6 aprovados em base temporária.
- Configuração Docker/Caddy preparada; a aplicação ainda não tem servidor, domínio/DNS, .env de produção ou URL pública.
- Email admin previsto: candidoshacal@gmail.com.

## Prioridade 1 — proteger os dados locais

- Fazer backup antes de qualquer migração da base carta_auto_testes.db.
- Nunca executar import_questions.py sem rever o código e fazer backup: o importador legado substitui perguntas e exige um TXT externo.
- Não enviar carta_auto_testes.db, backups, login.json, .env.test ou qualquer .env real para Git, ZIP ou outra IA.
- Usar iniciar_testar_web.bat para testes locais: ele mantém a base de teste em .test-data, separada da base normal.

## Prioridade 2 — ampliar a validação

- A suíte atual passa: registo/login, MFA, sessão revogada, recuperação de password, teste B/revisão, favoritos e administração.
- Acrescentar casos para categoria A com e sem B/B1, C, D, modo temático, novas, erradas, pool curto e licença expirada.
- Rever visualmente Chrome e Firefox em desktop/tablet/telemóvel e nos modos claro/escuro.
- Validar menus, dimensões, imagens de perguntas e todos os controlos no browser.
- Testar recuperação real por SMTP numa conta de demonstração antes de publicar.

## Prioridade 3 — preparar a segurança de produção

- Definir segredos únicos: SESSION_SECRET com pelo menos 40 caracteres e CAT_ADMIN_PASSWORD com pelo menos 14.
- Configurar opcionalmente uma chave Fernet independente em CAT_MFA_ENCRYPTION_KEY.
- Configurar SMTP, domínio, DNS e CORS; verificar HTTPS, backups/restauro e logs sem segredos.
- Fazer revisão manual dos endpoints restantes e dos limites de tentativas antes de expor o painel.

## Prioridade 4 — publicar com o dono

Antes de publicar, é necessário o servidor Docker Compose, acesso SSH, domínio/DNS, SMTP e os segredos de produção. Depois configurar o Caddyfile/CORS, iniciar Docker Compose, validar healthcheck/HTTPS, criar contas de demonstração, testar os fluxos e documentar backups. Não afirmar que está online antes de validar uma URL pública.

## Prompt de continuação

Continua Carta Auto Testes nesta pasta. Lê README.md, AI_HANDOFF.md, PROJECT_MAP.md, SEGURANCA.md e DEPLOYMENT_STATUS.md. Preserva a base carta_auto_testes.db e os PDFs; nunca executes o importador legado sem backup. Usa testes em base temporária. O MFA TOTP para ADMIN já está implementado; não o removas nem cries bypass em desenvolvimento. Faz os testes visuais nos browsers pretendidos e amplia os testes A/C/D. Para publicar, confirma com o dono servidor, domínio/DNS, SMTP e segredos reais. Nunca publiques .env, login.json, tokens ou base local.

