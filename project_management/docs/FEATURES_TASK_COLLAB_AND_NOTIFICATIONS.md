# Task Collaboration & Notification Features

## 1) Task Comments (Threaded + Mentions)

- Admin/Manager: add comments in task history page.
- Staff: add comments in own task history page.
- Supports threaded replies using optional parent comment id.
- Mention format: `@username` (or staff name token).
- Mention triggers email + WhatsApp webhook notification when configured.

## 2) Task Attachments

- Task-level file upload in task history pages.
- Allowed extensions:
  - `.pdf`, `.doc`, `.docx`, `.txt`, `.png`, `.jpg`, `.jpeg`, `.xlsx`, `.csv`
- Max file size:
  - `5 MB`

## 3) Reminder Integration

Management command:

```bash
python manage.py send_task_reminders
```

Sends due-tomorrow/overdue reminders based on staff notification settings.

Optional WhatsApp integration:

- set `WHATSAPP_WEBHOOK_URL` environment variable
- webhook payload:
  - `{ "to": "<number>", "message": "<text>" }`

## 4) Reports Export

Reports now support:

- CSV
- XLSX
- PDF

## 5) Activity/Audit Export + Retention

- Activity log export: CSV/XLSX
- Login audit export: CSV/XLSX

Retention command:

```bash
python manage.py purge_old_logs --days 180
```

or use default from setting:

- `LOG_RETENTION_DAYS` (default `180`)

