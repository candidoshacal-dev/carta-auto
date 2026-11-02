# Carta Auto Testes

Plataforma de treino do código da estrada para as categorias A, B, C e D. Projeto local e configuração de publicação incluídos.

## Iniciar localmente no Windows

1. Instale Python 3.10 ou superior.
2. Abra iniciar.bat.
3. Na primeira execução, o script instala as dependências e abre http://127.0.0.1:8000.

A conta inicial de demonstração é candidoshacal@gmail.com / admin123. No primeiro login, o administrador tem de configurar MFA TOTP. O arranque normal usa carta_auto_testes.db; o script iniciar_testar_web.bat usa uma base isolada em .test-data para não alterar os dados locais.

## Executar os testes automatizados

Num ambiente virtual, instale as dependências de desenvolvimento com `python -m pip install -r requirements-dev.txt` e execute `python -m pytest -q test_carta_auto.py`. Os testes usam uma base temporária copiada do seed e não alteram carta_auto_testes.db.

## Publicar num servidor com Docker

O projeto inclui Docker Compose, Caddy e um volume persistente para os dados. É necessário um servidor que aceite Docker Compose, um domínio cujo DNS aponte para esse servidor, e as portas 80/443 abertas.

1. Copie .env.example para .env.
2. Substitua YOUR_DOMAIN no .env e no Caddyfile pelo domínio real.
3. Gere SESSION_SECRET com: python -c "import secrets; print(secrets.token_urlsafe(48))".
4. Defina CAT_ADMIN_EMAIL e uma password administrativa única com pelo menos 14 caracteres.
5. Configure SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD e SMTP_FROM para habilitar a recuperação de password por email.
6. Execute docker compose up --build -d.
7. Aceda ao domínio por HTTPS; o Caddy solicita e renova o certificado TLS automaticamente depois de o DNS estar correto.

No primeiro arranque, o volume persistente é inicializado com a base de perguntas limpa (seed/carta_auto_testes_seed.db). Em cada arranque de produção, CAT_ADMIN_PASSWORD e CAT_ADMIN_EMAIL repõem as credenciais administrativas configuradas no .env. Guarde o .env fora do pacote e não o envie para a outra IA.

Para cópias de segurança, faça backup do volume carta_auto_testes_data. A imagem Docker não inclui o PDF nem a base SQLite de desenvolvimento; o seed incluído tem 2.594 perguntas (A: 298, B: 1.962, C: 157, D: 177), sem contas nem histórico. A base de desenvolvimento carta_auto_testes.db não deve ser partilhada: pode conter contas e histórico.

## Regras dos simuladores

Os formatos correspondem à prova teórica descrita nos artigos 43.º, 46.º e 47.º do RHLC:

| Categoria | Perguntas | Tempo | Aprovação |
|---|---:|---:|---:|
| B | 30 | 30 min | 27 certas (máx. 3 erros) |
| A sem B/B1 | 40: 30 comuns + 10 específicas A | 40 min | 36 certas (máx. 4 erros) |
| A com B/B1 | 10 específicas A | 10 min | 9 certas (máx. 1 erro) |
| C | 20 | 25 min | 18 certas (máx. 2 erros) |
| D | 20 | 25 min | 18 certas (máx. 2 erros) |

Os modos são Exame aleatório equilibrado por tema, Novas, Temático (um ou mais temas), Difícil (questões com mais erros globais) e Erradas (última resposta do aluno incorreta). Quando a lista Novas/Erradas é menor que o tamanho oficial, o teste usa as questões disponíveis e ajusta o tempo e o limite de erros proporcionalmente.

## Funcionalidades

- Registo, login por email/número de aluno, licenças e perfil do aluno.
- Categorias atribuídas pelo administrador.
- Testes cronometrados, aprovação/reprovação, revisão, histórico, erros, favoritas e estatísticas.
- Painel de administração para alunos, licenças, categorias e questões.
- Tema claro/escuro e interface responsiva.
- Administração de questões e pesquisa por categoria/tema.

## Segurança e limites conhecidos

- As passwords novas usam PBKDF2-SHA256; os hashes antigos são aceites e atualizados após login bem-sucedido.
- Tokens de sessão são assinados e expiram após 12 horas. Em produção, o servidor exige uma SESSION_SECRET forte.
- CORS fica restrito às origens configuradas.
- Recuperação por email depende da configuração SMTP. Sem SMTP, o pedido falha sem revelar nem alterar a password.
- A base local mantém SQLite e está preparada para uma única instância do serviço. Para escala horizontal, migre para PostgreSQL.
- O banco inclui referências de imagem em image_path; 2.413 das 2.594 perguntas atuais têm imagem associada. Os PDFs fornecidos ficam no projeto para referência.
- MFA TOTP é obrigatório para todas as contas ADMIN, incluindo no desenvolvimento. Antes de uso público, configure domínio, DNS, SMTP e backups, e faça revisão funcional e visual nos browsers pretendidos.
- O importador import_questions.py espera C:/Users/candi/Desktop/teste_utf8.txt e apaga as perguntas atuais antes de importar. Faça backup e confirme o arquivo antes de executar.

## Arquivos para continuação

Leia AI_HANDOFF.md, PROJECT_MAP.md, TODO_MANUTENCAO_IA.md, SEGURANCA.md e DEPLOYMENT_STATUS.md antes de alterar ou publicar a aplicação. Os testes de API existentes passam em base temporária; a publicação ainda depende de servidor, domínio, DNS, SMTP e segredos de produção. O painel admin exige MFA TOTP.
