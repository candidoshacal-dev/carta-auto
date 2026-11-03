@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  echo Execute iniciar.bat uma vez para preparar as dependencias.
  pause
  exit /b 1
)
if not exist .test-data mkdir .test-data
if not exist .test-data\carta_auto_testes_test.db copy seed\carta_auto_testes_seed.db .test-data\carta_auto_testes_test.db >nul
set CAT_ENV=development
set CAT_DB_PATH=%CD%\.test-data\carta_auto_testes_test.db
set HOST=127.0.0.1
set PORT=8001
set SESSION_SECRET=chave-teste-local-apenas-para-a-base-isolada-carta-auto
echo ============================================
echo Carta Auto Testes - Servidor de testes local
echo ============================================
echo URL: http://127.0.0.1:8001/
echo Acesso: 127.0.0.1 only - sem exposicao externa
echo ============================================
echo Base isolada: .test-data\carta_auto_testes_test.db
echo Conta admin inicial: candidoshacal@gmail.com / admin123
echo O primeiro login pede configuracao MFA TOTP.
echo Para terminar: Ctrl+C
echo ============================================
start "" http://127.0.0.1:8001
.venv\Scripts\python.exe server.py
endlocal
