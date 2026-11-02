@echo off
cd /d "%~dp0"
set CAT_ENV=development
set HOST=127.0.0.1
set PORT=8000
if exist .venv\Scripts\python.exe (
  .venv\Scripts\python.exe server.py
) else (
  python server.py
)
