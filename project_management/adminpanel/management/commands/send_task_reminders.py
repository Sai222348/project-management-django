import json
import os
from datetime import date, timedelta
from urllib import request as urllib_request

from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand

from adminpanel.models import Staff, StaffNotificationSetting, Task, TaskActivityLog


def _send_whatsapp(numbers, message):
    webhook_url = os.getenv('WHATSAPP_WEBHOOK_URL', '').strip()
    if not webhook_url:
        return 0
    sent = 0
    for number in numbers:
        if not number:
            continue
        payload = json.dumps({'to': number, 'message': message}).encode('utf-8')
        req = urllib_request.Request(
            webhook_url,
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urllib_request.urlopen(req, timeout=6) as resp:
                if 200 <= resp.status < 300:
                    sent += 1
        except Exception:
            continue
    return sent


class Command(BaseCommand):
    help = "Send due-tomorrow and overdue reminders via email/WhatsApp."

    def handle(self, *args, **options):
        today = date.today()
        due_tomorrow_date = today + timedelta(days=1)
        email_sent = 0
        whatsapp_sent = 0
        recipients = 0

        for staff in Staff.objects.all():
            setting, _ = StaffNotificationSetting.objects.get_or_create(staff=staff)
            if not setting.email_reminders and not setting.in_app_reminders:
                continue

            due_tomorrow_qs = Task.objects.filter(
                assigned_to=staff,
                due_date=due_tomorrow_date,
            ).exclude(status=Task.STATUS_COMPLETED)
            overdue_qs = Task.objects.filter(
                assigned_to=staff,
                due_date__lt=today,
            ).exclude(status=Task.STATUS_COMPLETED)

            if not due_tomorrow_qs.exists() and not overdue_qs.exists():
                continue

            lines = [f"Hi {staff.name},", "", "Task reminders:", ""]
            if due_tomorrow_qs.exists():
                lines.append("Due Tomorrow:")
                for t in due_tomorrow_qs[:20]:
                    lines.append(f"- {t.title} (Due: {t.due_date})")
                lines.append("")
            if overdue_qs.exists():
                lines.append("Overdue:")
                for t in overdue_qs[:20]:
                    lines.append(f"- {t.title} (Due: {t.due_date})")
                lines.append("")
            lines.append("Please update status/report in the staff panel.")
            message = "\n".join(lines)

            if setting.email_reminders and staff.email:
                try:
                    email_sent += send_mail(
                        subject='Task Reminder: Due Tomorrow / Overdue',
                        message=message,
                        from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@project-management.local'),
                        recipient_list=[staff.email],
                        fail_silently=False,
                    )
                except Exception:
                    pass

            if setting.in_app_reminders and staff.contact_number:
                whatsapp_sent += _send_whatsapp([staff.contact_number], message)

            recipients += 1

            sample_task = due_tomorrow_qs.first() or overdue_qs.first()
            if sample_task:
                TaskActivityLog.objects.create(
                    task=sample_task,
                    action=TaskActivityLog.ACTION_UPDATED,
                    old_status=sample_task.status,
                    new_status=sample_task.status,
                    changed_by_staff=staff,
                    note='Automated reminder sent',
                )

        self.stdout.write(
            self.style.SUCCESS(
                f"Reminder run complete. staff={recipients}, email_sent={email_sent}, whatsapp_sent={whatsapp_sent}"
            )
        )

