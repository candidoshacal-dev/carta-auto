# Passagem do projeto Carta Auto Testes

## Objetivo
Manter a plataforma de treino de código da estrada para categorias A, B, C e D, preservando dados, logo, PDFs e regras do simulador.

## Leia primeiro
README.md, PROJECT_MAP.md, TODO_MANUTENCAO_IA.md, SEGURANCA.md e DEPLOYMENT_STATUS.md. Não execute import_questions.py sem analisar e fazer backup: o importador legado substitui perguntas e espera um TXT que não acompanha o projeto.

## Componentes
- server.py: API FastAPI, autenticação/MFA, licenças, testes, resultados, imagens e administração.
- database.py: SQLite, migrações e hashing de passwords.
- static/index.html, static/app.js, static/styles.css: interface web.
- static/assets/questions: imagens associadas às perguntas.
- carta_auto_testes.db: base local que pode conter contas/histórico; preservada no computador e excluída do ZIP de passagem.
- seed/carta_auto_testes_seed.db: seed limpo, sem contas/histórico, com 2.594 perguntas; A 298, B 1.962, C 157, D 177.
- testes_codigo_completo corrigidas.pdf e testes_codigo_completo_com_imagens.pdf: documentos do projeto.
- Dockerfile, docker-compose.yml, entrypoint.sh, Caddyfile e .env.example: preparação de publicação.
- test_carta_auto.py: testes de API em base temporária.
- iniciar_testar_web.bat: servidor local isolado, porta 8001 e base .test-data.

## Regras dos exames implementadas
- B: 30 perguntas, 30 min, 27 certas.
- A sem B/B1: 40 perguntas (30 comuns + 10 específicas A), 40 min, 36 certas.
- A com B/B1: 10 perguntas específicas, 10 min, 9 certas.
- C e D: 20 perguntas, 25 min, 18 certas.
- Modos: exame aleatório, temático, novas, erradas e difíceis.

## Segurança e dados
- TOTP é obrigatório para todas as contas ADMIN, também em desenvolvimento. O primeiro login não cria sessão até configurar MFA.
- Códigos de recuperação são de uso único; TOTP repetido é recusado.
- Para recuperar MFA fora de banda, use reset_admin_mfa.py a partir do servidor/local e verifique a identidade do administrador.
- Não partilhe .env, .env.test, login.json, tokens, carta_auto_testes.db nem backups.
- A base seed foi limpa de contas; a base de desenvolvimento foi preservada sem alterações pelos testes.

## Estado e próximos passos
- Os 7 testes de API atuais passam em base temporária.
- Ampliar testes A/C/D e cenários temáticos/novas/erradas.
- Rever visualmente Chrome e Firefox nos dois temas e vários tamanhos; essa verificação ainda está pendente.
- Configurar servidor, domínio/DNS, SMTP e segredos de produção antes de publicar.

Email admin previsto: candidoshacal@gmail.com. Nunca usar a password de demonstração em produção.

