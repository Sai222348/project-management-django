from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from adminpanel.models import LoginAudit, TaskActivityLog


class Command(BaseCommand):
    help = "Purge login/activity logs older than retention period."

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=getattr(settings, 'LOG_RETENTION_DAYS', 180),
            help='Retention period in days (default from settings.LOG_RETENTION_DAYS).',
        )

    def handle(self, *args, **options):
        days = max(int(options['days']), 1)
        cutoff = timezone.now() - timedelta(days=days)

        login_deleted, _ = LoginAudit.objects.filter(attempted_at__lt=cutoff).delete()
        activity_deleted, _ = TaskActivityLog.objects.filter(created_at__lt=cutoff).delete()

        self.stdout.write(
            self.style.SUCCESS(
                f"Purge complete. retention_days={days}, login_deleted={login_deleted}, activity_deleted={activity_deleted}"
            )
        )

