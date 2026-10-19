@echo off
py -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -e ".[dev]"
if not exist .env copy .env.example .env
echo Installed. Run: phishshield web
cmd /k
