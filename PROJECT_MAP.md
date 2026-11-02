# Mapa do projeto

## Componentes principais

- server.py: API FastAPI, login, MFA TOTP, licenças, seleção/correção dos testes, estatísticas, rotas admin e upload de imagens.
- database.py: SQLite, migrações de tabelas, hashing e recuperação offline MFA.
- static/index.html: documento principal.
- static/app.js: navegação, testes, formulários, temas e renderização.
- static/styles.css: layout responsivo, temas e componentes.
- static/assets/logonovocartaauto.png: logo pequeno do cabeçalho.
- static/assets/logonovocartaauto_hero.png: logo grande da página inicial.
- static/assets/questions: imagens associadas às perguntas.
- carta_auto_testes.db: base local de desenvolvimento; pode conter contas e histórico.
- seed/carta_auto_testes_seed.db: seed de perguntas sem contas, 2.594 perguntas A/B/C/D.
- test_carta_auto.py: testes API com uma base temporária em .test-tmp.
- iniciar.bat: prepara dependências e inicia o site local normal.
- iniciar_testar_web.bat: inicia servidor isolado na porta 8001 usando .test-data.
- reset_admin_mfa.py: recuperação admin offline que invalida sessões.
- Dockerfile/docker-compose.yml, Caddyfile, entrypoint.sh e .env.example: implantação Docker com HTTPS Caddy.
- README.md: instalação e utilização.
- TODO_MANUTENCAO_IA.md: tarefas e sequência de continuação.
- SEGURANCA.md: MFA e condições antes de exposição pública.
- AI_HANDOFF.md: instruções de passagem.
- DEPLOYMENT_STATUS.md: estado de publicação.

## Fluxo do exame

1. POST /api/tests/start escolhe perguntas por categoria, modo e tema.
2. O navegador mostra uma questão e controla o temporizador.
3. POST /api/tests/{id}/submit calcula aprovação, regista respostas e histórico.
4. GET /api/tests/{id}/review devolve respostas e correção.
5. Perfil/admin consultam estatísticas e questões mais falhadas.

A publicação não foi feita; consulte DEPLOYMENT_STATUS.md.
