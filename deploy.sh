#!/usr/bin/env bash
set -euo pipefail

# --- CONFIG ---
DOMAIN="${1:-YOUR_DOMAIN}"
PROJECT_DIR="/opt/carta-auto-testes"
TMP_SRC="$(pwd)"

# 1. INFRA E REDE
echo "Criando rede isolada carta-auto-net..."
docker network inspect carta-auto-net >/dev/null 2>&1 || docker network create carta-auto-net

# 2. PREPARA PRODUÇÃO
mkdir -p "$PROJECT_DIR"
rsync -a --exclude='.env' --exclude='carta_auto_testes.db' --exclude='login.json' --exclude='backups' --exclude='.venv' "$TMP_SRC"/ "$PROJECT_DIR"/

# .env produção
cd "$PROJECT_DIR"
if [ ! -f .env ]; then
  cp .env.example .env
  SECRET=$(openssl rand -base64 48)
  sed -i "s|SESSION_SECRET=.*|SESSION_SECRET=$SECRET|" .env
  sed -i "s|CAT_ENV=.*|CAT_ENV=production|" .env
  sed -i "s|CORS_ORIGINS=.*|CORS_ORIGINS=https://${DOMAIN}|" .env
fi

# Caddyfile domínio
cat > Caddyfile <<EOF
${DOMAIN} {
  encode zstd gzip
  reverse_proxy app:8000
}
EOF

# .dockerignore para segurança
cat > .dockerignore <<'EOF'
.env
.env.test
login.json
carta_auto_testes.db
backups/
*.db
*.db.backup*
EOF

# 3. DOCKER COMPOSE
cat > docker-compose.yml <<'EOF'
services:
  app:
    build: .
    restart: unless-stopped
    env_file:
      - .env
    volumes:
      - carta_auto_testes_data:/data
    expose:
      - "8000"
    networks:
      - carta-auto-net
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/', timeout=4)"]
      interval: 30s
      timeout: 6s
      retries: 3
      start_period: 25s
  proxy:
    image: caddy:2-alpine
    restart: unless-stopped
    depends_on:
      app:
        condition: service_healthy
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    networks:
      - carta-auto-net
volumes:
  carta_auto_testes_data:
  caddy_data:
  caddy_config:
networks:
  carta-auto-net:
    external: true
EOF

# 4. BUILD E SUBIR
docker compose -p carta-auto-testes up -d --build

# 5. VALIDAÇÃO
echo "Aguardando arranque..."
sleep 15
curl -skI https://${DOMAIN} | head -n 5 || true

echo "DEPLOY CONCLUÍDO"
echo "URL: https://${DOMAIN}"
echo "Primeiro acesso ADMIN: gere MFA com reset_admin_mfa.py no servidor depois de localizar a base"
echo "SMTP e ADMIN_PASSWORD devem ser configurados em .env antes do uso em produção"
