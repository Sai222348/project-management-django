# Database & Backup Plan

## 1) Production Database Switch (PostgreSQL)

Set these environment variables in production:

- `DJANGO_DB_ENGINE=postgres`
- `POSTGRES_DB=project_management`
- `POSTGRES_USER=postgres`
- `POSTGRES_PASSWORD=<strong-password>`
- `POSTGRES_HOST=127.0.0.1`
- `POSTGRES_PORT=5432`

Install PostgreSQL driver:

```bash
pip install psycopg[binary]
```

Run migrations:

```bash
python manage.py migrate
```

## 2) Daily Backup Plan

- Schedule one daily full backup using Windows Task Scheduler / cron.
- Keep at least 14 daily copies + 4 weekly copies.
- Store backups outside app server disk when possible.

PowerShell backup script:

`scripts/backup_db.ps1`

PowerShell restore script:

`scripts/restore_db.ps1`

Windows scheduler registration script:

`scripts/register_daily_backup_task.ps1`

Run once:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\register_daily_backup_task.ps1 -ProjectDir .
```

## 3) Restore Test (Monthly)

1. Create a staging database.
2. Restore latest backup into staging.
3. Run:
   - `python manage.py migrate`
   - smoke login test
   - sample read/write test for staff/task data
4. Record restore duration and issues.

Restore/backup drill log file:

`logs/backup_restore_drill.log`

## 4) SQLite (Local Dev)

- Continue using SQLite for local development.
- Optional local backup command:
  - `copy db.sqlite3 backups\db_%DATE%.sqlite3`
