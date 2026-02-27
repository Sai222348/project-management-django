# Project Management (Django)

Production-ready Django app with admin/staff workflows and REST API.

## Quick Start (After Clone)

```powershell
git clone <repo-url>
cd project-management-django\project_management
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
Copy-Item .env.dev.example .env.dev
.\venv\Scripts\python.exe .\manage.py migrate
.\venv\Scripts\python.exe .\manage.py runserver
```

## Required Environment Variables

Use `project_management/.env.production.example` as template.

Minimum required in production:
- `DJANGO_DEBUG=0`
- `DJANGO_SECRET_KEY=<strong-random-secret>`
- `DJANGO_ALLOWED_HOSTS=<comma-separated-hosts>`
- `DJANGO_DB_ENGINE=postgres`
- `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_HOST`, `POSTGRES_PORT`

## Deployment Command

From `project_management/` directory:

```powershell
.\venv\Scripts\python.exe .\manage.py migrate
.\venv\Scripts\python.exe .\manage.py collectstatic --noinput
```

For WSGI servers (Linux):

```bash
gunicorn config.wsgi:application --bind 0.0.0.0:$PORT
```

## GitHub Push

```powershell
git init
git add .
git commit -m "Initial production-ready setup"
git branch -M main
git remote add origin <your-repo-url>
git push -u origin main
```

## Notes

- Do not commit real `.env` files.
- Rotate any secret values that were previously exposed.

## Local URL (Important)

- Local development server supports only HTTP.
- Use: http://127.0.0.1:8000/
- Do not use https:// with manage.py runserver (it will show 400 bad request).
- HTTPS is available only after production deployment with SSL.
