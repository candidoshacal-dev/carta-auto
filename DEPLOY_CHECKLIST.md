# Carta Auto Testes — Deploy Checklist Produção

## 1. Infraestrutura e Rede
- [ ] Domínio apontado para IP do VPS
- [ ] Rede Docker isolada: `docker network create carta-auto-net`
- [ ] Portas abertas: 80, 443, 8000 interno
- [ ] Caddyfile com domínio e reverse_proxy app:8000

## 2. Segurança e Dados
- [ ] .env baseado em .env.example com CAT_ENV=production
- [ ] SESSION_SECRET gerado com `openssl rand -base64 48`
- [ ] CAT_ADMIN_PASSWORD único ≥14 chars
- [ ] SMTP configurado para recuperação
- [ ] .env, carta_auto_testes.db, login.json, backups NÃO copiados
- [ ] Base inicia limpa em /data

## 3. MFA Admin
- [ ] Primeiro acesso: executar `python reset_admin_mfa.py` no servidor
- [ ] Verificar TOTP ativo para ADMIN

## 4. Deploy Docker
- [ ] Copiar código limpo + docker-compose.prod.yml + Caddyfile
- [ ] `docker compose -f docker-compose.prod.yml up -d --build`
- [ ] Restart policy: unless-stopped

## 5. Validação Pós-Deploy
- [ ] HTTPS responde: `curl -skI https://dominio`
- [ ] Login admin funciona
- [ ] Login estudante funciona
- [ ] Temas claro/escuro alternam
- [ ] Teste inicia e imagens carregam
- [ ] Logs sem erros: `docker compose logs -f`

## 6. Manutenção
- [ ] Backups automáticos da pasta /data
- [ ] Monitorização de disco e logs
- [ ] Atualizações via rede isolada

URL final: https://SEU_DOMINIO
