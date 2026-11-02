@echo off
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  py -m venv .venv
  if errorlevel 1 goto erro
)
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto erro
.venv\Scripts\python.exe -c "from database import init_db; init_db()"
if errorlevel 1 goto erro
echo A abrir Carta Auto Testes em http://127.0.0.1:8000
start "" http://127.0.0.1:8000
.venv\Scripts\python.exe server.py
goto fim
:erro
echo Nao foi possivel preparar o ambiente. Verifique Python e a ligacao a internet.
pause
:fim
