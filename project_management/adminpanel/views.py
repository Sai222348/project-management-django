import csv
import calendar
from datetime import date, timedelta
import json
import logging
import os
import re
from importlib import import_module
from io import BytesIO
from urllib import request as urllib_request
from urllib.parse import urlencode

from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import Group
from django.core.paginator import Paginator
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.db.models import Q
from django.db.models import Count
from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.dateparse import parse_date
from django.views.decorators.cache import never_cache

from .models import (
    HelpdeskTicket,
    LoginAudit,
    Project,
    Staff,
    StaffAttendance,
    StaffDocument,
    StaffGoal,
    StaffLeaveRequest,
    StaffNotificationSetting,
    TaskComment,
    StaffTimesheetEntry,
    SystemSetting,
    Task,
    TaskActivityLog,
    TaskDailyUpdate,
)
from .forms import (
    HelpdeskTicketForm,
    ProjectForm,
    StaffForm,
    StaffAttendanceForm,
    TaskAttachmentForm,
    TaskCommentForm,
    StaffDocumentUploadForm,
    StaffGoalForm,
    StaffLeaveApplyForm,
    StaffNotificationSettingForm,
    StaffProfileForm,
    StaffTaskUpdateForm,
    StaffTimesheetDailyForm,
    SystemSettingsForm,
    TaskCreateForm,
    TaskForm,
)

logger = logging.getLogger(__name__)


def _clean_report_text(text):
    cleaned = (text or '').strip()
    prefix = 'Day To Day Report:'
    if cleaned.lower().startswith(prefix.lower()):
        return cleaned[len(prefix):].strip()
    return cleaned


def _get_client_ip(request):
    forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def _log_login_attempt(request, login_type, username, user=None, is_success=False, failure_reason=''):
    LoginAudit.objects.create(
        attempted_username=(username or '').strip(),
        user=user,
        login_type=login_type,
        is_success=is_success,
        failure_reason=failure_reason,
        ip_address=_get_client_ip(request),
    )


def _log_task_activity(task, action, request=None, old_status='', new_status='', note=''):
    user = request.user if request and request.user.is_authenticated else None
    staff_actor = None
    if user:
        staff_actor = Staff.objects.filter(user=user).first()
    TaskActivityLog.objects.create(
        task=task,
        action=action,
        old_status=old_status or '',
        new_status=new_status or '',
        changed_by_user=user,
        changed_by_staff=staff_actor,
        note=(note or '').strip(),
    )


def _get_system_setting():
    setting, _ = SystemSetting.objects.get_or_create(
        id=1,
        defaults={
            'company_name': 'Project Management',
            'working_days': 'Mon,Tue,Wed,Thu,Fri',
            'reminder_time': '09:00',
            'support_email': 'support@example.com',
            'support_phone': '',
        },
    )
    return setting


def _build_error_context(extra=None):
    setting = _get_system_setting()
    context = {
        'company_name': setting.company_name,
        'support_email': setting.support_email,
        'support_phone': setting.support_phone,
    }
    if extra:
        context.update(extra)
    return context


def _is_admin_user(user):
    return user.is_authenticated and (
        user.is_superuser
        or user.is_staff
        or user.groups.filter(name='Admin').exists()
    )


def _is_manager_user(user):
    return user.is_authenticated and user.groups.filter(name='Manager').exists()


def _is_admin_or_manager_user(user):
    return _is_admin_user(user) or _is_manager_user(user)


def _assign_role_group(user, role_value):
    role = (role_value or '').strip().lower()
    manager_group, _ = Group.objects.get_or_create(name='Manager')
    staff_group, _ = Group.objects.get_or_create(name='Staff')
    admin_group, _ = Group.objects.get_or_create(name='Admin')

    user.groups.remove(manager_group, staff_group, admin_group)
    if role == Staff.ROLE_MANAGER.lower():
        user.groups.add(manager_group)
    elif role == Staff.ROLE_ADMIN.lower():
        user.groups.add(admin_group)
    else:
        user.groups.add(staff_group)


def _build_history_updates(task):
    raw_updates = list(
        TaskDailyUpdate.objects.filter(task=task).order_by('-report_date', '-id')
    )
    if not raw_updates and task.day_report.strip():
        fallback = TaskDailyUpdate(
            task=task,
            project_topic=task.project_topic,
            status=task.status,
            report_text=task.day_report.strip(),
            report_date=task.start_date,
        )
        fallback.display_text = _clean_report_text(fallback.report_text)
        return [fallback]

    deduped_updates = []
    seen_dates = set()
    for update in raw_updates:
        if update.report_date in seen_dates:
            continue
        seen_dates.add(update.report_date)
        update.display_text = _clean_report_text(update.report_text)
        deduped_updates.append(update)
    return deduped_updates


def _parse_report_filters(request):
    date_from_raw = request.GET.get('date_from', '').strip()
    date_to_raw = request.GET.get('date_to', '').strip()
    staff_id_raw = request.GET.get('staff', '').strip()
    status = request.GET.get('status', '').strip()

    date_from = parse_date(date_from_raw) if date_from_raw else None
    date_to = parse_date(date_to_raw) if date_to_raw else None

    try:
        staff_id = int(staff_id_raw) if staff_id_raw else None
    except (TypeError, ValueError):
        staff_id = None

    valid_statuses = {choice[0] for choice in Task.STATUS_CHOICES}
    if status not in valid_statuses:
        status = ''

    tasks = Task.objects.select_related('assigned_to', 'project').order_by('-due_date', '-id')
    if date_from:
        tasks = tasks.filter(due_date__gte=date_from)
    if date_to:
        tasks = tasks.filter(due_date__lte=date_to)
    if staff_id:
        tasks = tasks.filter(assigned_to_id=staff_id)
    if status:
        tasks = tasks.filter(status=status)

    return tasks, {
        'date_from': date_from_raw,
        'date_to': date_to_raw,
        'staff_id': str(staff_id) if staff_id else '',
        'status': status,
    }


def _build_filter_labels(filter_state):
    labels = []
    if filter_state.get('date_from'):
        labels.append(f"From: {filter_state['date_from']}")
    if filter_state.get('date_to'):
        labels.append(f"To: {filter_state['date_to']}")
    if filter_state.get('staff_name'):
        labels.append(f"Staff: {filter_state['staff_name']}")
    if filter_state.get('status'):
        labels.append(f"Status: {filter_state['status']}")
    return labels


def _build_csv_response(filename, headers, rows):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    writer = csv.writer(response)
    writer.writerow(headers)
    for row in rows:
        writer.writerow(row)
    return response


def _build_xlsx_response(filename, title, headers, rows, filter_labels):
    try:
        Workbook = import_module('openpyxl').Workbook
    except Exception:
        fallback_rows = [('Error', 'openpyxl is not installed')]
        return _build_csv_response(filename.replace('.xlsx', '.csv'), ['Info', 'Value'], fallback_rows)
    wb = Workbook()
    ws = wb.active
    ws.title = 'Report'
    ws.append([title])
    if filter_labels:
        ws.append(['Filters', ', '.join(filter_labels)])
    ws.append([])
    ws.append(list(headers))
    for row in rows:
        ws.append(list(row))
    stream = BytesIO()
    wb.save(stream)
    response = HttpResponse(
        stream.getvalue(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    )
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


def _pdf_escape(value):
    return str(value).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')


def _build_pdf_response(filename, title, headers, rows, filter_labels):
    lines = [title]
    if filter_labels:
        lines.append('Filters: ' + ', '.join(filter_labels))
    lines.append('')
    lines.append(' | '.join(headers))
    lines.append('-' * 90)
    max_rows = 38
    for row in rows[:max_rows]:
        lines.append(' | '.join(str(item) if item not in (None, '') else '-' for item in row))
    if len(rows) > max_rows:
        lines.append(f"... {len(rows) - max_rows} more rows not shown")

    content_lines = [
        'BT',
        '/F1 10 Tf',
        '50 790 Td',
        '14 TL',
    ]
    for line in lines:
        content_lines.append(f'({_pdf_escape(line)}) Tj')
        content_lines.append('T*')
    content_lines.append('ET')
    stream_data = '\n'.join(content_lines).encode('latin-1', 'replace')

    objects = [
        b'<< /Type /Catalog /Pages 2 0 R >>',
        b'<< /Type /Pages /Count 1 /Kids [3 0 R] >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
        b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
        b'<< /Length ' + str(len(stream_data)).encode('ascii') + b' >>\nstream\n' + stream_data + b'\nendstream',
    ]

    pdf = b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += f'{index} 0 obj\n'.encode('ascii')
        pdf += obj + b'\nendobj\n'

    xref_start = len(pdf)
    pdf += f'xref\n0 {len(objects) + 1}\n'.encode('ascii')
    pdf += b'0000000000 65535 f \n'
    for offset in offsets[1:]:
        pdf += f'{offset:010d} 00000 n \n'.encode('ascii')
    pdf += f'trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF'.encode('ascii')

    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


def _extract_mentions(text):
    raw = re.findall(r'@([A-Za-z0-9_.-]+)', text or '')
    mentions = []
    seen = set()
    for token in raw:
        normalized = token.strip().lower()
        if normalized and normalized not in seen:
            mentions.append(normalized)
            seen.add(normalized)
    return mentions


def _send_email_notification(recipients, subject, body):
    recipient_list = [mail for mail in recipients if mail]
    if not recipient_list:
        return 0
    try:
        return send_mail(
            subject=subject,
            message=body,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@project-management.local'),
            recipient_list=recipient_list,
            fail_silently=False,
        )
    except Exception:
        logger.exception("Email notification failed for recipients=%s", recipient_list)
        return 0


def _send_whatsapp_notification(numbers, message):
    webhook_url = os.getenv('WHATSAPP_WEBHOOK_URL', '').strip()
    if not webhook_url:
        return 0
    sent = 0
    for number in numbers:
        if not number:
            continue
        try:
            payload = json.dumps({'to': number, 'message': message}).encode('utf-8')
            req = urllib_request.Request(
                webhook_url,
                data=payload,
                headers={'Content-Type': 'application/json'},
                method='POST',
            )
            with urllib_request.urlopen(req, timeout=5) as resp:
                if 200 <= resp.status < 300:
                    sent += 1
        except Exception:
            logger.exception("WhatsApp notification failed for %s", number)
    return sent


def _notify_task_mentions(task, text, actor_name='System'):
    mentions = _extract_mentions(text)
    if not mentions:
        return {'email_sent': 0, 'whatsapp_sent': 0}
    staff_members = Staff.objects.select_related('user').all()
    matched = []
    mention_set = set(mentions)
    for row in staff_members:
        username = (row.user.username or '').strip().lower() if row.user else ''
        staff_name = (row.name or '').strip().lower()
        normalized_name = staff_name.replace(' ', '.')
        if username in mention_set or staff_name in mention_set or normalized_name in mention_set:
            matched.append(row)
    if not matched:
        return {'email_sent': 0, 'whatsapp_sent': 0}
    subject = f"[Task Mention] {task.title}"
    body = (
        f"You were mentioned by {actor_name}.\n\n"
        f"Task: {task.title}\n"
        f"Project: {task.project.name if task.project else task.project_topic or '-'}\n"
        f"Message: {text}\n"
    )
    emails = [s.email for s in matched if s.email]
    numbers = [s.contact_number for s in matched if s.contact_number]
    email_sent = _send_email_notification(emails, subject, body)
    whatsapp_sent = _send_whatsapp_notification(numbers, body)
    return {'email_sent': email_sent, 'whatsapp_sent': whatsapp_sent}


def _build_notification_context(tasks_queryset):
    today = date.today()
    due_tomorrow = (
        tasks_queryset
        .filter(due_date=today + timedelta(days=1))
        .exclude(status=Task.STATUS_COMPLETED)
        .order_by('due_date', 'id')
    )
    overdue = (
        tasks_queryset
        .filter(due_date__lt=today)
        .exclude(status=Task.STATUS_COMPLETED)
        .order_by('due_date', 'id')
    )
    return {
        'due_tomorrow_count': due_tomorrow.count(),
        'overdue_count': overdue.count(),
        'due_tomorrow_tasks': due_tomorrow[:5],
        'overdue_tasks': overdue[:5],
        'total_alerts': due_tomorrow.count() + overdue.count(),
    }


def _get_staff_notification_setting(staff):
    setting, _ = StaffNotificationSetting.objects.get_or_create(staff=staff)
    return setting


def _build_staff_notification_context(staff):
    setting = _get_staff_notification_setting(staff)
    tasks_queryset = Task.objects.filter(assigned_to=staff).select_related('project')
    active_tasks = tasks_queryset.exclude(status=Task.STATUS_COMPLETED)
    today = date.today()
    due_tomorrow = active_tasks.filter(due_date=today + timedelta(days=1)).order_by('due_date', 'id')
    overdue = active_tasks.filter(due_date__lt=today).order_by('due_date', 'id')

    mentions = []
    username = (staff.user.username if staff.user else '').strip()
    name_token = (staff.name or '').strip()
    mention_patterns = [f'@{username.lower()}'] if username else []
    if name_token:
        mention_patterns.append(f'@{name_token.lower()}')

    if setting.mention_enabled and setting.in_app_reminders and mention_patterns:
        updates = (
            TaskDailyUpdate.objects.filter(task__assigned_to=staff)
            .exclude(report_text='')
            .select_related('task')
            .order_by('-created_at')[:120]
        )
        activities = (
            TaskActivityLog.objects.filter(task__assigned_to=staff)
            .exclude(note='')
            .select_related('task')
            .order_by('-created_at')[:120]
        )
        for update in updates:
            report_lower = (update.report_text or '').lower()
            if any(pattern in report_lower for pattern in mention_patterns):
                mentions.append(
                    {
                        'source': 'Daily Update',
                        'task': update.task,
                        'text': _clean_report_text(update.report_text),
                        'created_at': update.created_at,
                    }
                )
        for log in activities:
            note_lower = (log.note or '').lower()
            if any(pattern in note_lower for pattern in mention_patterns):
                mentions.append(
                    {
                        'source': 'Activity',
                        'task': log.task,
                        'text': log.note,
                        'created_at': log.created_at,
                    }
                )
        mentions.sort(key=lambda item: item['created_at'], reverse=True)

    due_tomorrow_items = due_tomorrow[:10] if setting.in_app_reminders and setting.due_tomorrow_enabled else []
    overdue_items = overdue[:10] if setting.in_app_reminders and setting.overdue_enabled else []
    due_tomorrow_count = due_tomorrow.count() if setting.in_app_reminders and setting.due_tomorrow_enabled else 0
    overdue_count = overdue.count() if setting.in_app_reminders and setting.overdue_enabled else 0
    mention_count = len(mentions[:10]) if setting.in_app_reminders and setting.mention_enabled else 0

    return {
        'setting': setting,
        'due_tomorrow_tasks': due_tomorrow_items,
        'overdue_tasks': overdue_items,
        'mention_items': mentions[:10] if setting.in_app_reminders and setting.mention_enabled else [],
        'due_tomorrow_count': due_tomorrow_count,
        'overdue_count': overdue_count,
        'mention_count': mention_count,
        'total_notifications': due_tomorrow_count + overdue_count + mention_count,
    }


def _week_range_from_date(anchor_date):
    week_start = anchor_date - timedelta(days=anchor_date.weekday())
    week_end = week_start + timedelta(days=6)
    return week_start, week_end


def _build_staff_performance_context(staff):
    today = date.today()
    tasks = Task.objects.filter(assigned_to=staff)
    total_tasks = tasks.count()
    completed_tasks = tasks.filter(status=Task.STATUS_COMPLETED).count()
    overdue_tasks = tasks.filter(due_date__lt=today).exclude(status=Task.STATUS_COMPLETED).count()
    delay_percent = round((overdue_tasks / total_tasks) * 100, 2) if total_tasks else 0

    entries = StaffTimesheetEntry.objects.filter(staff=staff)
    total_hours = sum(float(row.hours_spent) for row in entries)
    productivity = round((completed_tasks / total_hours) * 100, 2) if total_hours else 0
    return {
        'total_tasks': total_tasks,
        'completed_tasks': completed_tasks,
        'overdue_tasks': overdue_tasks,
        'delay_percent': delay_percent,
        'total_logged_hours': round(total_hours, 2),
        'productivity_score': productivity,
    }


def _build_task_collaboration(task):
    comments = (
        TaskComment.objects.filter(task=task, parent__isnull=True)
        .select_related('staff', 'user')
        .prefetch_related('replies__staff', 'replies__user')
        .order_by('-created_at')
    )
    attachments = task.attachments.select_related('uploaded_by_staff', 'uploaded_by_user').all()
    return comments, attachments


def _faq_items():
    return [
        {
            'question': 'How do I update my task status?',
            'answer': 'Open My Tasks, select your task, and use Update Status/Report.',
        },
        {
            'question': 'How do I submit daily timesheet?',
            'answer': 'Go to Timesheet Daily and submit work date, hours, and summary.',
        },
        {
            'question': 'How can I request leave?',
            'answer': 'Go to Attendance & Leave, open Apply Leave, and submit date range with reason.',
        },
        {
            'question': 'Where can I check reminders and alerts?',
            'answer': 'Open Notifications from the staff sidebar to see due, overdue, and mention alerts.',
        },
    ]



# ---------------- AUTH ---------------- #

def csrf_failure(request, reason=''):
    logger.warning(
        "CSRF failure path=%s method=%s user=%s reason=%s",
        request.path,
        request.method,
        getattr(request.user, 'username', 'anonymous') if hasattr(request, 'user') and request.user.is_authenticated else 'anonymous',
        reason,
    )
    return render(
        request,
        '403.html',
        _build_error_context({'reason': reason}),
        status=403,
    )


def error_403(request, exception=None):
    logger.warning(
        "403 error path=%s method=%s user=%s detail=%s",
        request.path,
        request.method,
        request.user.username if hasattr(request, 'user') and request.user.is_authenticated else 'anonymous',
        str(exception or ''),
    )
    return render(
        request,
        '403.html',
        _build_error_context(),
        status=403,
    )


def error_404(request, exception):
    logger.info(
        "404 error path=%s method=%s user=%s",
        request.path,
        request.method,
        request.user.username if hasattr(request, 'user') and request.user.is_authenticated else 'anonymous',
    )
    return render(
        request,
        '404.html',
        _build_error_context({'request_path': request.path}),
        status=404,
    )


def error_500(request):
    logger.exception(
        "500 error path=%s method=%s user=%s",
        request.path,
        request.method,
        request.user.username if hasattr(request, 'user') and request.user.is_authenticated else 'anonymous',
    )
    return render(
        request,
        '500.html',
        _build_error_context(),
        status=500,
    )

def home(request):
    if request.user.is_authenticated:
        if _is_admin_or_manager_user(request.user):
            return redirect('dashboard')
        return redirect('staff_dashboard')
    return redirect('login')


def admin_required(view_func):
    return user_passes_test(
        _is_admin_user,
        login_url='admin_login',
    )(view_func)


def admin_or_manager_required(view_func):
    return user_passes_test(
        _is_admin_or_manager_user,
        login_url='admin_login',
    )(view_func)


@never_cache
def login_selector(request):
    return render(request, 'adminpanel/login_selector.html')


def staff_required(view_func):
    return user_passes_test(
        lambda user: user.is_authenticated and Staff.objects.filter(user=user).exists() and not _is_admin_or_manager_user(user),
        login_url='staff_login',
    )(view_func)


@never_cache
def admin_login_view(request):
    error = ''
    if request.method == 'POST':
        username = (request.POST.get('username') or '').strip()
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user and _is_admin_or_manager_user(user):
            login(request, user)
            _log_login_attempt(
                request,
                login_type='Admin',
                username=username,
                user=user,
                is_success=True,
            )
            return redirect('dashboard')
        error = 'Username or password is incorrect. Please try again.'
        _log_login_attempt(
            request,
            login_type='Admin',
            username=username,
            user=user if user and user.is_authenticated else None,
            is_success=False,
            failure_reason=error,
        )

    return render(request, 'adminpanel/admin_login.html', {'error': error})


@never_cache
def staff_login_view(request):
    error = ''
    if request.method == 'POST':
        username = (request.POST.get('username') or '').strip()
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        staff = Staff.objects.filter(user=user).first() if user else None
        if user and staff and not _is_admin_or_manager_user(user):
            login(request, user)
            _log_login_attempt(
                request,
                login_type='Staff',
                username=username,
                user=user,
                is_success=True,
            )
            return redirect('staff_dashboard')
        error = 'Username or password is incorrect. Please try again.'
        _log_login_attempt(
            request,
            login_type='Staff',
            username=username,
            user=user if user and user.is_authenticated else None,
            is_success=False,
            failure_reason=error,
        )

    return render(request, 'adminpanel/staff_login.html', {'error': error})


def logout_view(request):
    logout(request)
    return redirect('login')


# ---------------- DASHBOARD ---------------- #

@admin_or_manager_required
def dashboard(request):
    tasks_qs = Task.objects.select_related('assigned_to', 'project')
    total_tasks = tasks_qs.count()
    total_staff = Staff.objects.count()
    completed = tasks_qs.filter(status=Task.STATUS_COMPLETED).count()
    pending = tasks_qs.filter(status=Task.STATUS_PENDING).count()
    in_progress = tasks_qs.filter(status=Task.STATUS_IN_PROGRESS).count()
    completion_rate = round((completed / total_tasks) * 100) if total_tasks else 0
    recent_tasks = tasks_qs.order_by('-id')[:5]
    staff_counts = (
        tasks_qs.values('assigned_to__name')
        .annotate(task_count=Count('id'))
        .order_by('assigned_to__name')
    )
    notification_context = _build_notification_context(tasks_qs)
    context = {
        'task_count': total_tasks,
        'staff_count': total_staff,
        'completed': completed,
        'pending': pending,
        'in_progress': in_progress,
        'completion_rate': completion_rate,
        'recent_tasks': recent_tasks,
        'staff_labels_json': json.dumps([row['assigned_to__name'] for row in staff_counts]),
        'staff_data_json': json.dumps([row['task_count'] for row in staff_counts]),
    }
    context.update(notification_context)

    return render(request, 'adminpanel/dashboard.html', context)


# ---------------- REPORTS ---------------- #

@admin_or_manager_required
def login_audit_trail(request):
    query = request.GET.get('q', '').strip()
    result_filter = request.GET.get('result', '').strip().lower()
    login_type = request.GET.get('type', '').strip()
    date_from_raw = request.GET.get('date_from', '').strip()
    date_to_raw = request.GET.get('date_to', '').strip()
    export_format = request.GET.get('format', '').strip().lower()
    date_from = parse_date(date_from_raw) if date_from_raw else None
    date_to = parse_date(date_to_raw) if date_to_raw else None

    audits = LoginAudit.objects.select_related('user').all()
    if query:
        audits = audits.filter(
            Q(attempted_username__icontains=query)
            | Q(user__username__icontains=query)
        )
    if result_filter == 'success':
        audits = audits.filter(is_success=True)
    elif result_filter == 'failed':
        audits = audits.filter(is_success=False)
    if login_type in {LoginAudit.LOGIN_TYPE_ADMIN, LoginAudit.LOGIN_TYPE_STAFF}:
        audits = audits.filter(login_type=login_type)
    if date_from:
        audits = audits.filter(attempted_at__date__gte=date_from)
    if date_to:
        audits = audits.filter(attempted_at__date__lte=date_to)
    audits = audits.order_by('-attempted_at')
    audit_rows = [
        (
            item.attempted_at.isoformat(sep=' ', timespec='seconds'),
            item.attempted_username or '-',
            item.user.username if item.user else '-',
            item.login_type,
            'Success' if item.is_success else 'Failed',
            item.ip_address or '-',
            item.failure_reason or '-',
        )
        for item in audits[:2000]
    ]
    if export_format == 'csv':
        return _build_csv_response(
            'login_audit_trail.csv',
            ['Time', 'Attempted Username', 'User', 'Type', 'Result', 'IP', 'Reason'],
            audit_rows,
        )
    if export_format == 'xlsx':
        return _build_xlsx_response(
            'login_audit_trail.xlsx',
            'Login Audit Trail',
            ['Time', 'Attempted Username', 'User', 'Type', 'Result', 'IP', 'Reason'],
            audit_rows,
            [],
        )
    if export_format == 'pdf':
        return _build_pdf_response(
            'login_audit_trail.pdf',
            'Login Audit Trail',
            ['Time', 'Attempted Username', 'User', 'Type', 'Result', 'IP', 'Reason'],
            audit_rows,
            [],
        )
    paginator = Paginator(audits, 25)
    page_obj = paginator.get_page(request.GET.get('page'))
    query_params = request.GET.copy()
    query_params.pop('page', None)

    context = {
        'audits': page_obj.object_list,
        'page_obj': page_obj,
        'query': query,
        'selected_result': result_filter,
        'selected_type': login_type,
        'selected_date_from': date_from_raw,
        'selected_date_to': date_to_raw,
        'failed_count': LoginAudit.objects.filter(is_success=False).count(),
        'success_count': LoginAudit.objects.filter(is_success=True).count(),
        'page_query': query_params.urlencode(),
        'last_successful_login': LoginAudit.objects.filter(
            user=request.user,
            is_success=True,
        ).order_by('-attempted_at').first(),
    }
    return render(request, 'adminpanel/login_audit_trail.html', context)


@admin_required
def system_settings(request):
    setting = _get_system_setting()
    form = SystemSettingsForm(request.POST or None, instance=setting)
    if form.is_valid():
        form.save()
        return redirect('system_settings')
    return render(
        request,
        'adminpanel/system_settings.html',
        {'form': form},
    )


@admin_required
def activity_log(request):
    query = request.GET.get('q', '').strip()
    action = request.GET.get('action', '').strip()
    date_from_raw = request.GET.get('date_from', '').strip()
    date_to_raw = request.GET.get('date_to', '').strip()
    export_format = request.GET.get('format', '').strip().lower()
    date_from = parse_date(date_from_raw) if date_from_raw else None
    date_to = parse_date(date_to_raw) if date_to_raw else None
    logs = TaskActivityLog.objects.select_related(
        'task',
        'changed_by_user',
        'changed_by_staff',
        'task__assigned_to',
    )
    if query:
        logs = logs.filter(
            Q(task__title__icontains=query)
            | Q(changed_by_user__username__icontains=query)
            | Q(changed_by_staff__name__icontains=query)
            | Q(note__icontains=query)
        )
    action_values = {value for value, _ in TaskActivityLog.ACTION_CHOICES}
    if action in action_values:
        logs = logs.filter(action=action)
    if date_from:
        logs = logs.filter(created_at__date__gte=date_from)
    if date_to:
        logs = logs.filter(created_at__date__lte=date_to)
    logs = logs.order_by('-created_at')
    log_rows = [
        (
            item.created_at.isoformat(sep=' ', timespec='seconds'),
            item.task.title,
            item.action,
            item.old_status or '-',
            item.new_status or '-',
            item.changed_by_staff.name if item.changed_by_staff else (item.changed_by_user.username if item.changed_by_user else 'System'),
            item.note or '-',
        )
        for item in logs[:3000]
    ]
    if export_format == 'csv':
        return _build_csv_response(
            'activity_log.csv',
            ['Time', 'Task', 'Action', 'Old Status', 'New Status', 'Changed By', 'Note'],
            log_rows,
        )
    if export_format == 'xlsx':
        return _build_xlsx_response(
            'activity_log.xlsx',
            'Task Activity Log',
            ['Time', 'Task', 'Action', 'Old Status', 'New Status', 'Changed By', 'Note'],
            log_rows,
            [],
        )
    paginator = Paginator(logs, 25)
    page_obj = paginator.get_page(request.GET.get('page'))
    query_params = request.GET.copy()
    query_params.pop('page', None)

    return render(
        request,
        'adminpanel/activity_log.html',
        {
            'logs': page_obj.object_list,
            'page_obj': page_obj,
            'query': query,
            'selected_action': action,
            'selected_date_from': date_from_raw,
            'selected_date_to': date_to_raw,
            'action_choices': TaskActivityLog.ACTION_CHOICES,
            'page_query': query_params.urlencode(),
        },
    )

@admin_or_manager_required
def reports_dashboard(request):
    tasks, filter_state = _parse_report_filters(request)
    selected_staff = Staff.objects.filter(id=filter_state['staff_id']).first() if filter_state['staff_id'] else None
    filter_state['staff_name'] = selected_staff.name if selected_staff else ''
    export_format = request.GET.get('format', '').strip().lower()

    total_tasks = tasks.count()
    completed = tasks.filter(status=Task.STATUS_COMPLETED).count()
    in_progress = tasks.filter(status=Task.STATUS_IN_PROGRESS).count()
    pending = tasks.filter(status=Task.STATUS_PENDING).count()
    overdue = tasks.filter(due_date__lt=date.today()).exclude(status=Task.STATUS_COMPLETED).count()
    completion_rate = round((completed / total_tasks) * 100) if total_tasks else 0

    rows = [
        ('Total Tasks', total_tasks),
        ('Completed', completed),
        ('In Progress', in_progress),
        ('Pending', pending),
        ('Overdue', overdue),
        ('Completion Rate %', completion_rate),
    ]
    if export_format == 'csv':
        return _build_csv_response('reports_dashboard.csv', ['Metric', 'Value'], rows)
    if export_format == 'xlsx':
        return _build_xlsx_response(
            'reports_dashboard.xlsx',
            'Reports Dashboard',
            ['Metric', 'Value'],
            rows,
            _build_filter_labels(filter_state),
        )
    if export_format == 'pdf':
        return _build_pdf_response(
            'reports_dashboard.pdf',
            'Reports Dashboard',
            ['Metric', 'Value'],
            rows,
            _build_filter_labels(filter_state),
        )

    staff_options = Staff.objects.order_by('name')
    return render(
        request,
        'adminpanel/reports_dashboard.html',
        {
            'total_tasks': total_tasks,
            'completed': completed,
            'in_progress': in_progress,
            'pending': pending,
            'overdue': overdue,
            'completion_rate': completion_rate,
            'recent_tasks': tasks[:10],
            'staff_options': staff_options,
            'status_choices': Task.STATUS_CHOICES,
            'selected_date_from': filter_state['date_from'],
            'selected_date_to': filter_state['date_to'],
            'selected_staff': filter_state['staff_id'],
            'selected_status': filter_state['status'],
        },
    )


@admin_or_manager_required
def staff_performance_report(request):
    tasks, filter_state = _parse_report_filters(request)
    selected_staff = Staff.objects.filter(id=filter_state['staff_id']).first() if filter_state['staff_id'] else None
    filter_state['staff_name'] = selected_staff.name if selected_staff else ''
    export_format = request.GET.get('format', '').strip().lower()
    today = date.today()

    rows_qs = (
        tasks.values('assigned_to__name')
        .annotate(
            total_tasks=Count('id'),
            completed_tasks=Count('id', filter=Q(status=Task.STATUS_COMPLETED)),
            in_progress_tasks=Count('id', filter=Q(status=Task.STATUS_IN_PROGRESS)),
            pending_tasks=Count('id', filter=Q(status=Task.STATUS_PENDING)),
            overdue_tasks=Count('id', filter=Q(due_date__lt=today) & ~Q(status=Task.STATUS_COMPLETED)),
        )
        .order_by('assigned_to__name')
    )
    performance_rows = list(rows_qs)

    csv_rows = [
        (
            row['assigned_to__name'],
            row['total_tasks'],
            row['completed_tasks'],
            row['in_progress_tasks'],
            row['pending_tasks'],
            row['overdue_tasks'],
        )
        for row in performance_rows
    ]
    if export_format == 'csv':
        return _build_csv_response(
            'staff_performance_report.csv',
            ['Staff', 'Total', 'Completed', 'In Progress', 'Pending', 'Overdue'],
            csv_rows,
        )
    if export_format == 'xlsx':
        return _build_xlsx_response(
            'staff_performance_report.xlsx',
            'Staff Performance Report',
            ['Staff', 'Total', 'Completed', 'In Progress', 'Pending', 'Overdue'],
            csv_rows,
            _build_filter_labels(filter_state),
        )
    if export_format == 'pdf':
        return _build_pdf_response(
            'staff_performance_report.pdf',
            'Staff Performance Report',
            ['Staff', 'Total', 'Completed', 'In Progress', 'Pending', 'Overdue'],
            csv_rows,
            _build_filter_labels(filter_state),
        )

    staff_options = Staff.objects.order_by('name')
    return render(
        request,
        'adminpanel/staff_performance_report.html',
        {
            'rows': performance_rows,
            'staff_options': staff_options,
            'status_choices': Task.STATUS_CHOICES,
            'selected_date_from': filter_state['date_from'],
            'selected_date_to': filter_state['date_to'],
            'selected_staff': filter_state['staff_id'],
            'selected_status': filter_state['status'],
        },
    )


@admin_or_manager_required
def overdue_tasks_report(request):
    tasks, filter_state = _parse_report_filters(request)
    selected_staff = Staff.objects.filter(id=filter_state['staff_id']).first() if filter_state['staff_id'] else None
    filter_state['staff_name'] = selected_staff.name if selected_staff else ''
    export_format = request.GET.get('format', '').strip().lower()

    overdue_tasks = tasks.filter(due_date__lt=date.today()).exclude(status=Task.STATUS_COMPLETED)
    rows = [
        (
            task.title,
            task.project.name if task.project else (task.project_topic or '-'),
            task.assigned_to.name,
            task.status,
            task.start_date.isoformat(),
            task.due_date.isoformat(),
        )
        for task in overdue_tasks
    ]
    if export_format == 'csv':
        return _build_csv_response(
            'overdue_tasks_report.csv',
            ['Title', 'Project', 'Assigned To', 'Status', 'Start Date', 'Due Date'],
            rows,
        )
    if export_format == 'xlsx':
        return _build_xlsx_response(
            'overdue_tasks_report.xlsx',
            'Overdue Tasks Report',
            ['Title', 'Project', 'Assigned To', 'Status', 'Start Date', 'Due Date'],
            rows,
            _build_filter_labels(filter_state),
        )
    if export_format == 'pdf':
        return _build_pdf_response(
            'overdue_tasks_report.pdf',
            'Overdue Tasks Report',
            ['Title', 'Project', 'Assigned To', 'Status', 'Start Date', 'Due Date'],
            rows,
            _build_filter_labels(filter_state),
        )

    staff_options = Staff.objects.order_by('name')
    return render(
        request,
        'adminpanel/overdue_tasks_report.html',
        {
            'tasks': overdue_tasks,
            'staff_options': staff_options,
            'status_choices': Task.STATUS_CHOICES,
            'selected_date_from': filter_state['date_from'],
            'selected_date_to': filter_state['date_to'],
            'selected_staff': filter_state['staff_id'],
            'selected_status': filter_state['status'],
            'overdue_count': overdue_tasks.count(),
        },
    )


# ---------------- PROJECTS ---------------- #

@admin_or_manager_required
def project_list(request):
    query = request.GET.get('q', '').strip()
    projects = Project.objects.annotate(task_count=Count('tasks')).order_by('name')
    if query:
        projects = projects.filter(
            Q(name__icontains=query)
            | Q(client__icontains=query)
            | Q(status__icontains=query)
        )
    return render(
        request,
        'adminpanel/project_list.html',
        {'projects': projects, 'query': query},
    )


@never_cache
@admin_or_manager_required
def project_create(request):
    form = ProjectForm(request.POST or None)
    if form.is_valid():
        form.save()
        return redirect('projects')
    return render(request, 'adminpanel/project_form.html', {'form': form})


@never_cache
@admin_or_manager_required
def project_update(request, pk):
    project = get_object_or_404(Project, id=pk)
    form = ProjectForm(request.POST or None, instance=project)
    if form.is_valid():
        form.save()
        return redirect('projects')
    return render(request, 'adminpanel/project_form.html', {'form': form, 'project': project})


@admin_or_manager_required
def project_detail(request, pk):
    project = get_object_or_404(Project, id=pk)
    tasks = Task.objects.filter(project=project).select_related('assigned_to').order_by('due_date', '-id')
    return render(
        request,
        'adminpanel/project_detail.html',
        {'project': project, 'tasks': tasks},
    )


# ---------------- STAFF ---------------- #

@admin_or_manager_required
def staff_list(request):
    query = request.GET.get('q', '').strip()
    staff_qs = Staff.objects.select_related('user').order_by('name')
    if query:
        staff_qs = staff_qs.filter(
            Q(name__icontains=query)
            | Q(email__icontains=query)
            | Q(role__icontains=query)
            | Q(reporting_officer__icontains=query)
            | Q(availability_status__icontains=query)
            | Q(user__username__icontains=query)
        )
    paginator = Paginator(staff_qs, 20)
    page_obj = paginator.get_page(request.GET.get('page'))
    query_params = request.GET.copy()
    query_params.pop('page', None)
    return render(
        request,
        'adminpanel/staff_list.html',
        {
            'staff': page_obj.object_list,
            'page_obj': page_obj,
            'query': query,
            'staff_count': staff_qs.count(),
            'can_manage_staff': _is_admin_user(request.user),
            'page_query': query_params.urlencode(),
        },
    )


@admin_or_manager_required
def staff_detail(request, pk):
    staff = get_object_or_404(Staff, id=pk)
    tasks = Task.objects.filter(assigned_to=staff).order_by('due_date')
    active_count = tasks.filter(status__in=[Task.STATUS_PENDING, Task.STATUS_IN_PROGRESS]).count()
    overdue_count = tasks.filter(due_date__lt=date.today()).exclude(status=Task.STATUS_COMPLETED).count()
    return render(
        request,
        'adminpanel/staff_detail.html',
        {
            'staff': staff,
            'tasks': tasks,
            'active_count': active_count,
            'overdue_count': overdue_count,
        }
    )


@admin_or_manager_required
def staff_workload(request):
    today = date.today()
    rows = (
        Staff.objects.annotate(
            total_tasks=Count('task'),
            active_tasks=Count(
                'task',
                filter=Q(task__status__in=[Task.STATUS_PENDING, Task.STATUS_IN_PROGRESS]),
            ),
            overdue_tasks=Count(
                'task',
                filter=Q(task__due_date__lt=today) & ~Q(task__status=Task.STATUS_COMPLETED),
            ),
        )
        .order_by('-overdue_tasks', '-active_tasks', 'name')
    )
    return render(
        request,
        'adminpanel/staff_workload.html',
        {'rows': rows},
    )


@never_cache
@admin_required
def staff_create(request):
    form = StaffForm(request.POST or None)
    if form.is_valid():
        user_model = get_user_model()
        user = user_model.objects.create_user(
            username=form.cleaned_data['username'],
            password=form.cleaned_data['password'],
            email=form.cleaned_data['email'],
        )
        _assign_role_group(user, form.cleaned_data['role'])
        staff = form.save(commit=False)
        staff.user = user
        staff.save()
        return redirect('staff')
    return render(request, 'adminpanel/staff_form.html', {'form': form})


@never_cache
@admin_required
def staff_update(request, pk):
    staff = get_object_or_404(Staff, id=pk)
    form = StaffForm(request.POST or None, instance=staff)
    if form.is_valid():
        user_model = get_user_model()
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']

        user = staff.user
        if user is None:
            if not password:
                form.add_error('password', 'Password is required to create login.')
                return render(request, 'adminpanel/staff_form.html', {'form': form})
            user = user_model.objects.create_user(
                username=username,
                password=password,
                email=form.cleaned_data['email'],
            )
            staff.user = user
        else:
            user.username = username
            user.email = form.cleaned_data['email']
            if password:
                user.set_password(password)
            user.save()
        _assign_role_group(user, form.cleaned_data['role'])

        form.save()
        return redirect('staff')
    return render(request, 'adminpanel/staff_form.html', {'form': form})


@never_cache
@admin_required
def staff_delete(request, pk):
    staff = get_object_or_404(Staff, id=pk)
    if request.method == 'POST':
        linked_user = staff.user
        staff.delete()
        if linked_user:
            linked_user.delete()
        return redirect('staff')
    return render(request, 'adminpanel/staff_confirm_delete.html', {'staff': staff})


# ---------------- TASKS ---------------- #

@admin_or_manager_required
def task_list(request):
    query = request.GET.get('q', '').strip()
    status = request.GET.get('status', '').strip()
    due_date = request.GET.get('due_date', '').strip()
    staff_id = request.GET.get('staff', '').strip()

    tasks = Task.objects.select_related('assigned_to', 'project').order_by('-id')

    if query:
        tasks = tasks.filter(
            Q(title__icontains=query)
            | Q(project_topic__icontains=query)
            | Q(project__name__icontains=query)
            | Q(assigned_to__name__icontains=query)
        )
    if status in {choice[0] for choice in Task.STATUS_CHOICES}:
        tasks = tasks.filter(status=status)
    parsed_due_date = parse_date(due_date) if due_date else None
    if parsed_due_date:
        tasks = tasks.filter(due_date=parsed_due_date)
    if staff_id.isdigit():
        tasks = tasks.filter(assigned_to_id=int(staff_id))

    bulk_message = ''
    if request.method == 'POST':
        if not _is_admin_user(request.user):
            raise PermissionDenied("Only admin users can modify tasks.")
        selected_ids = request.POST.getlist('task_ids')
        action = request.POST.get('bulk_action', '').strip()
        selected_tasks = Task.objects.filter(id__in=selected_ids)

        if not selected_ids:
            bulk_message = 'Please select at least one task.'
        elif action == 'mark_complete':
            tasks_to_update = list(selected_tasks.exclude(status=Task.STATUS_COMPLETED))
            updated_count = selected_tasks.exclude(status=Task.STATUS_COMPLETED).update(status=Task.STATUS_COMPLETED)
            for task in tasks_to_update:
                _log_task_activity(
                    task,
                    TaskActivityLog.ACTION_MARKED_COMPLETED,
                    request=request,
                    old_status=task.status,
                    new_status=Task.STATUS_COMPLETED,
                    note='Bulk action from task list',
                )
            bulk_message = f'{updated_count} task(s) marked as completed.'
        elif action == 'reassign':
            reassign_to = request.POST.get('reassign_to', '').strip()
            if not reassign_to.isdigit():
                bulk_message = 'Please choose a staff member to reassign.'
            else:
                assignee = Staff.objects.filter(id=int(reassign_to)).first()
                if not assignee:
                    bulk_message = 'Selected staff not found.'
                elif assignee.availability_status != Staff.AVAILABILITY_AVAILABLE:
                    bulk_message = 'Selected staff is not available for reassignment.'
                else:
                    to_reassign = list(selected_tasks.select_related('assigned_to'))
                    updated_count = selected_tasks.update(assigned_to_id=assignee.id)
                    for task in to_reassign:
                        _log_task_activity(
                            task,
                            TaskActivityLog.ACTION_REASSIGNED,
                            request=request,
                            old_status=task.status,
                            new_status=task.status,
                            note=f"Reassigned from {task.assigned_to.name} to {assignee.name}",
                        )
                    bulk_message = f'{updated_count} task(s) reassigned.'
        else:
            bulk_message = 'Please choose a valid bulk action.'

        params = {
            'q': query,
            'status': status,
            'due_date': due_date,
            'staff': staff_id,
        }
        if bulk_message:
            params['bulk_message'] = bulk_message
        return redirect(f"{request.path}?{urlencode(params)}")

    paginator = Paginator(tasks, 20)
    page_obj = paginator.get_page(request.GET.get('page'))
    query_params = request.GET.copy()
    query_params.pop('page', None)
    bulk_message = request.GET.get('bulk_message', '').strip()
    staff_options = Staff.objects.order_by('name')
    available_staff_options = Staff.objects.filter(
        availability_status=Staff.AVAILABILITY_AVAILABLE
    ).order_by('name')

    return render(
        request,
        'adminpanel/task_list.html',
        {
            'tasks': page_obj.object_list,
            'page_obj': page_obj,
            'query': query,
            'selected_status': status,
            'selected_due_date': due_date,
            'selected_staff': staff_id,
            'staff_options': staff_options,
            'available_staff_options': available_staff_options,
            'status_choices': Task.STATUS_CHOICES,
            'bulk_message': bulk_message,
            'can_manage_tasks': _is_admin_user(request.user),
            'page_query': query_params.urlencode(),
        },
    )


@never_cache
@admin_required
def task_create(request):
    form = TaskCreateForm(request.POST or None)
    if form.is_valid():
        task = form.save()
        if task.project and task.project_topic != task.project.name:
            task.project_topic = task.project.name
            task.save(update_fields=['project_topic'])
        if task.day_report.strip():
            TaskDailyUpdate.objects.create(
                task=task,
                project_topic=task.project.name if task.project else task.project_topic,
                status=task.status,
                report_text=task.day_report.strip(),
                report_date=task.start_date,
            )
        _log_task_activity(
            task,
            TaskActivityLog.ACTION_CREATED,
            request=request,
            new_status=task.status,
            note='Task created',
        )
        return redirect('tasks')
    return render(request, 'adminpanel/task_form.html', {'form': form})


@never_cache
@admin_required
def task_update(request, pk):
    task = get_object_or_404(Task, id=pk)
    old_status = task.status
    old_assigned_to_id = task.assigned_to_id
    old_report = task.day_report
    form = TaskForm(request.POST or None, instance=task)
    if form.is_valid():
        updated_task = form.save(commit=False)
        if updated_task.project:
            updated_task.project_topic = updated_task.project.name
        updated_task.save()
        if old_assigned_to_id != updated_task.assigned_to_id:
            _log_task_activity(
                updated_task,
                TaskActivityLog.ACTION_REASSIGNED,
                request=request,
                old_status=old_status,
                new_status=updated_task.status,
                note='Task reassigned from edit page',
            )
        if old_status != updated_task.status:
            _log_task_activity(
                updated_task,
                TaskActivityLog.ACTION_STATUS_CHANGED,
                request=request,
                old_status=old_status,
                new_status=updated_task.status,
                note='Status changed from task edit page',
            )
        if old_status == updated_task.status and old_assigned_to_id == updated_task.assigned_to_id:
            _log_task_activity(
                updated_task,
                TaskActivityLog.ACTION_UPDATED,
                request=request,
                old_status=old_status,
                new_status=updated_task.status,
                note='Task details updated',
            )
        if old_report != updated_task.day_report and updated_task.day_report.strip():
            _notify_task_mentions(
                updated_task,
                updated_task.day_report,
                actor_name=request.user.username,
            )
        return redirect('tasks')
    return render(request, 'adminpanel/task_form.html', {'form': form})


@never_cache
@admin_required
def task_delete(request, pk):
    task = get_object_or_404(Task, id=pk)
    if request.method == 'POST':
        task.delete()
        return redirect('tasks')
    return render(request, 'adminpanel/task_confirm_delete.html', {'task': task})


@staff_required
def staff_dashboard(request):
    staff = get_object_or_404(Staff, user=request.user)
    tasks = Task.objects.filter(assigned_to=staff).select_related('project', 'assigned_to')
    total_tasks = tasks.count()
    completed = tasks.filter(status=Task.STATUS_COMPLETED).count()
    pending = tasks.filter(status=Task.STATUS_PENDING).count()
    in_progress = tasks.filter(status=Task.STATUS_IN_PROGRESS).count()
    recent_tasks = tasks.order_by('due_date')[:5]
    notification_context = _build_notification_context(tasks)

    context = {
        'staff': staff,
        'total_tasks': total_tasks,
        'completed': completed,
        'pending': pending,
        'in_progress': in_progress,
        'recent_tasks': recent_tasks,
    }
    context.update(notification_context)
    staff_notification_context = _build_staff_notification_context(staff)
    context.update(
        {
            'notification_total': staff_notification_context['total_notifications'],
            'mention_count': staff_notification_context['mention_count'],
        }
    )
    return render(request, 'adminpanel/staff_dashboard.html', context)


@staff_required
def staff_profile(request):
    staff = get_object_or_404(Staff, user=request.user)
    assigned_tasks = Task.objects.filter(assigned_to=staff)
    context = {
        'staff': staff,
        'total_tasks': assigned_tasks.count(),
        'active_tasks': assigned_tasks.filter(
            status__in=[Task.STATUS_PENDING, Task.STATUS_IN_PROGRESS]
        ).count(),
        'completed_tasks': assigned_tasks.filter(status=Task.STATUS_COMPLETED).count(),
    }
    return render(request, 'adminpanel/staff_profile.html', context)


@never_cache
@staff_required
def staff_profile_edit(request):
    staff = get_object_or_404(Staff, user=request.user)
    original_role = staff.role
    original_reporting_officer = staff.reporting_officer
    form = StaffProfileForm(request.POST or None, instance=staff)
    if form.is_valid():
        updated_staff = form.save(commit=False)
        # Staff cannot change role hierarchy fields from self-service profile.
        updated_staff.role = original_role
        updated_staff.reporting_officer = original_reporting_officer
        updated_staff.save()
        if staff.user and staff.user.email != updated_staff.email:
            staff.user.email = updated_staff.email
            staff.user.save(update_fields=['email'])
        return redirect('staff_profile')
    return render(request, 'adminpanel/staff_profile_edit.html', {'staff': staff, 'form': form})


@never_cache
@staff_required
def staff_change_password(request):
    staff = get_object_or_404(Staff, user=request.user)
    form = PasswordChangeForm(request.user, request.POST or None)
    if form.is_valid():
        user = form.save()
        update_session_auth_hash(request, user)
        return redirect('staff_profile')
    return render(request, 'adminpanel/staff_change_password.html', {'staff': staff, 'form': form})


@staff_required
def staff_task_list(request):
    staff = get_object_or_404(Staff, user=request.user)
    selected_tab = (request.GET.get('tab') or '').strip()
    tasks = (
        Task.objects.filter(assigned_to=staff)
        .select_related('project')
        .prefetch_related('daily_updates')
        .order_by('due_date')
    )
    if selected_tab == 'pending':
        tasks = tasks.filter(status=Task.STATUS_PENDING)
    elif selected_tab == 'in-progress':
        tasks = tasks.filter(status=Task.STATUS_IN_PROGRESS)
    elif selected_tab == 'completed':
        tasks = tasks.filter(status=Task.STATUS_COMPLETED)

    for task in tasks:
        updates = list(task.daily_updates.all())
        # Backward compatibility for tasks created before update-history model.
        if not updates and task.day_report.strip():
            updates = [
                TaskDailyUpdate(
                    task=task,
                    project_topic=task.project_topic,
                    status=task.status,
                    report_text=task.day_report.strip(),
                    report_date=task.start_date,
                )
            ]
        task.updates_for_display = updates
        task.latest_update = updates[-1] if updates else None
        task.latest_update_text = (
            _clean_report_text(task.latest_update.report_text)
            if task.latest_update else ''
        )
    return render(
        request,
        'adminpanel/staff_my_tasks.html',
        {
            'staff': staff,
            'tasks': tasks,
            'selected_tab': selected_tab,
            'pending_count': Task.objects.filter(assigned_to=staff, status=Task.STATUS_PENDING).count(),
            'in_progress_count': Task.objects.filter(assigned_to=staff, status=Task.STATUS_IN_PROGRESS).count(),
            'completed_count': Task.objects.filter(assigned_to=staff, status=Task.STATUS_COMPLETED).count(),
        },
    )


@staff_required
def staff_task_detail(request, pk):
    staff = get_object_or_404(Staff, user=request.user)
    task = get_object_or_404(
        Task.objects.select_related('assigned_to', 'project'),
        id=pk,
        assigned_to=staff,
    )
    updates = _build_history_updates(task)
    latest_update = updates[0] if updates else None
    return render(
        request,
        'adminpanel/staff_task_detail.html',
        {
            'staff': staff,
            'task': task,
            'latest_update': latest_update,
            'updates_count': len(updates),
        },
    )


@staff_required
def staff_notifications(request):
    staff = get_object_or_404(Staff, user=request.user)
    context = {
        'staff': staff,
    }
    context.update(_build_staff_notification_context(staff))
    return render(request, 'adminpanel/staff_notifications.html', context)


@never_cache
@staff_required
def staff_notification_settings(request):
    staff = get_object_or_404(Staff, user=request.user)
    setting = _get_staff_notification_setting(staff)
    form = StaffNotificationSettingForm(request.POST or None, instance=setting)
    if form.is_valid():
        form.save()
        return redirect('staff_notification_settings')
    return render(
        request,
        'adminpanel/staff_notification_settings.html',
        {
            'staff': staff,
            'form': form,
        },
    )


@staff_required
def staff_attendance(request):
    staff = get_object_or_404(Staff, user=request.user)
    initial = {'attendance_date': date.today()}
    form = StaffAttendanceForm(request.POST or None, initial=initial)
    if form.is_valid():
        attendance_date = form.cleaned_data['attendance_date']
        attendance, _ = StaffAttendance.objects.get_or_create(
            staff=staff,
            attendance_date=attendance_date,
        )
        attendance.check_in = form.cleaned_data.get('check_in')
        attendance.check_out = form.cleaned_data.get('check_out')
        attendance.status = form.cleaned_data['status']
        attendance.note = form.cleaned_data.get('note', '')
        attendance.save()
        return redirect('staff_attendance')

    records = StaffAttendance.objects.filter(staff=staff).order_by('-attendance_date', '-id')[:60]
    return render(
        request,
        'adminpanel/staff_attendance.html',
        {
            'staff': staff,
            'form': form,
            'records': records,
        },
    )


@never_cache
@staff_required
def staff_apply_leave(request):
    staff = get_object_or_404(Staff, user=request.user)
    form = StaffLeaveApplyForm(request.POST or None, staff=staff)
    if form.is_valid():
        leave_request = form.save(commit=False)
        leave_request.staff = staff
        leave_request.status = StaffLeaveRequest.STATUS_PENDING
        leave_request.save()
        return redirect('staff_leave_history')
    return render(
        request,
        'adminpanel/staff_apply_leave.html',
        {
            'staff': staff,
            'form': form,
        },
    )


@staff_required
def staff_leave_history(request):
    staff = get_object_or_404(Staff, user=request.user)
    leave_requests = StaffLeaveRequest.objects.filter(staff=staff).order_by('-applied_at')
    return render(
        request,
        'adminpanel/staff_leave_history.html',
        {
            'staff': staff,
            'leave_requests': leave_requests,
        },
    )


@staff_required
def staff_availability_calendar(request):
    staff = get_object_or_404(Staff, user=request.user)
    today = date.today()
    try:
        year = int(request.GET.get('year', today.year))
    except (TypeError, ValueError):
        year = today.year
    try:
        month = int(request.GET.get('month', today.month))
    except (TypeError, ValueError):
        month = today.month

    if month < 1 or month > 12:
        month = today.month

    month_days = calendar.Calendar(firstweekday=0).monthdatescalendar(year, month)
    leave_requests = StaffLeaveRequest.objects.filter(
        staff=staff,
        status__in=[StaffLeaveRequest.STATUS_PENDING, StaffLeaveRequest.STATUS_APPROVED],
        start_date__lte=max(week[-1] for week in month_days),
        end_date__gte=min(week[0] for week in month_days),
    )

    leave_by_day = {}
    for leave in leave_requests:
        cursor = leave.start_date
        while cursor <= leave.end_date:
            leave_by_day[cursor] = leave.status
            cursor += timedelta(days=1)

    weeks = []
    for week in month_days:
        week_rows = []
        for day in week:
            week_rows.append(
                {
                    'date': day,
                    'in_month': day.month == month,
                    'leave_status': leave_by_day.get(day, ''),
                    'is_today': day == today,
                }
            )
        weeks.append(week_rows)

    prev_month = month - 1
    prev_year = year
    next_month = month + 1
    next_year = year
    if prev_month == 0:
        prev_month = 12
        prev_year -= 1
    if next_month == 13:
        next_month = 1
        next_year += 1

    return render(
        request,
        'adminpanel/staff_availability_calendar.html',
        {
            'staff': staff,
            'weeks': weeks,
            'display_month_name': date(year, month, 1).strftime('%B %Y'),
            'prev_month': prev_month,
            'prev_year': prev_year,
            'next_month': next_month,
            'next_year': next_year,
            'availability_status': staff.availability_status,
            'leave_until': staff.leave_until,
        },
    )


@staff_required
def staff_timesheet_daily(request):
    staff = get_object_or_404(Staff, user=request.user)
    form = StaffTimesheetDailyForm(
        request.POST or None,
        staff=staff,
        initial={'work_date': date.today()},
    )
    if form.is_valid():
        entry = form.save(commit=False)
        entry.staff = staff
        entry.save()
        return redirect('staff_timesheet_daily')
    entries = StaffTimesheetEntry.objects.filter(staff=staff).select_related('task')[:20]
    return render(
        request,
        'adminpanel/staff_timesheet_daily.html',
        {
            'staff': staff,
            'form': form,
            'entries': entries,
        },
    )


@staff_required
def staff_timesheet_weekly(request):
    staff = get_object_or_404(Staff, user=request.user)
    week_param = (request.GET.get('week_start') or '').strip()
    week_start = parse_date(week_param) if week_param else None
    if not week_start:
        week_start, _ = _week_range_from_date(date.today())
    week_end = week_start + timedelta(days=6)

    entries = StaffTimesheetEntry.objects.filter(
        staff=staff,
        work_date__gte=week_start,
        work_date__lte=week_end,
    ).select_related('task').order_by('work_date', 'id')
    total_hours = round(sum(float(item.hours_spent) for item in entries), 2)

    prev_start = week_start - timedelta(days=7)
    next_start = week_start + timedelta(days=7)

    return render(
        request,
        'adminpanel/staff_timesheet_weekly.html',
        {
            'staff': staff,
            'entries': entries,
            'week_start': week_start,
            'week_end': week_end,
            'total_hours': total_hours,
            'prev_start': prev_start,
            'next_start': next_start,
        },
    )


@staff_required
def staff_worklog_history(request):
    staff = get_object_or_404(Staff, user=request.user)
    entries = StaffTimesheetEntry.objects.filter(staff=staff).select_related('task')
    return render(
        request,
        'adminpanel/staff_worklog_history.html',
        {
            'staff': staff,
            'entries': entries,
        },
    )


@staff_required
def staff_performance_dashboard(request):
    staff = get_object_or_404(Staff, user=request.user)
    context = {'staff': staff}
    context.update(_build_staff_performance_context(staff))
    return render(request, 'adminpanel/staff_performance_dashboard.html', context)


@never_cache
@staff_required
def staff_goal_tracker(request):
    staff = get_object_or_404(Staff, user=request.user)
    form = StaffGoalForm(request.POST or None)
    if form.is_valid():
        goal = form.save(commit=False)
        goal.staff = staff
        goal.save()
        return redirect('staff_goal_tracker')
    goals = StaffGoal.objects.filter(staff=staff)
    return render(
        request,
        'adminpanel/staff_goal_tracker.html',
        {
            'staff': staff,
            'form': form,
            'goals': goals,
        },
    )


@staff_required
def staff_documents(request):
    staff = get_object_or_404(Staff, user=request.user)
    category = (request.GET.get('category') or '').strip()
    documents = StaffDocument.objects.filter(Q(staff=staff) | Q(category__in=[StaffDocument.CATEGORY_POLICY, StaffDocument.CATEGORY_TEMPLATE]))
    if category in {choice[0] for choice in StaffDocument.CATEGORY_CHOICES}:
        documents = documents.filter(category=category)
    documents = documents.select_related('task', 'staff')
    return render(
        request,
        'adminpanel/staff_documents.html',
        {
            'staff': staff,
            'documents': documents,
            'category_choices': StaffDocument.CATEGORY_CHOICES,
            'selected_category': category,
        },
    )


@never_cache
@staff_required
def staff_document_upload(request):
    staff = get_object_or_404(Staff, user=request.user)
    form = StaffDocumentUploadForm(request.POST or None, request.FILES or None, staff=staff)
    if form.is_valid():
        doc = form.save(commit=False)
        doc.staff = staff
        doc.save()
        return redirect('staff_documents')
    return render(
        request,
        'adminpanel/staff_document_upload.html',
        {
            'staff': staff,
            'form': form,
        },
    )


@never_cache
@staff_required
def staff_helpdesk_create_ticket(request):
    staff = get_object_or_404(Staff, user=request.user)
    form = HelpdeskTicketForm(request.POST or None)
    if form.is_valid():
        ticket = form.save(commit=False)
        ticket.staff = staff
        ticket.save()
        return redirect('staff_helpdesk_history')
    return render(
        request,
        'adminpanel/staff_helpdesk_create_ticket.html',
        {
            'staff': staff,
            'form': form,
        },
    )


@staff_required
def staff_helpdesk_history(request):
    staff = get_object_or_404(Staff, user=request.user)
    tickets = HelpdeskTicket.objects.filter(staff=staff)
    return render(
        request,
        'adminpanel/staff_helpdesk_history.html',
        {
            'staff': staff,
            'tickets': tickets,
        },
    )


@staff_required
def staff_faq(request):
    staff = get_object_or_404(Staff, user=request.user)
    return render(
        request,
        'adminpanel/staff_faq.html',
        {
            'staff': staff,
            'faq_items': _faq_items(),
        },
    )


@admin_or_manager_required
def task_history(request, pk):
    task = get_object_or_404(Task.objects.select_related('assigned_to'), id=pk)
    updates = _build_history_updates(task)
    activity_logs = task.activity_logs.select_related('changed_by_user', 'changed_by_staff').all()[:20]
    comments, attachments = _build_task_collaboration(task)
    latest_update = updates[0] if updates else None
    first_update = updates[-1] if updates else None
    return render(
        request,
        'adminpanel/task_history.html',
        {
            'task': task,
            'updates': updates,
            'updates_count': len(updates),
            'latest_update': latest_update,
            'first_update': first_update,
            'is_updated_today': bool(
                latest_update and latest_update.report_date == date.today()
            ),
            'activity_logs': activity_logs,
            'comments': comments,
            'attachments': attachments,
            'comment_form': TaskCommentForm(),
            'attachment_form': TaskAttachmentForm(),
        },
    )


@never_cache
@admin_or_manager_required
def task_comment_create(request, pk):
    task = get_object_or_404(Task, id=pk)
    if request.method != 'POST':
        return redirect('task_history', pk=task.id)
    form = TaskCommentForm(request.POST)
    if form.is_valid():
        parent = None
        parent_id = form.cleaned_data.get('parent_id')
        if parent_id:
            parent = TaskComment.objects.filter(id=parent_id, task=task).first()
        comment = form.save(commit=False)
        comment.task = task
        comment.parent = parent
        comment.user = request.user
        comment.staff = Staff.objects.filter(user=request.user).first()
        comment.save()
        notify_result = _notify_task_mentions(
            task,
            comment.text,
            actor_name=request.user.username,
        )
        _log_task_activity(
            task,
            TaskActivityLog.ACTION_UPDATED,
            request=request,
            old_status=task.status,
            new_status=task.status,
            note=f"Comment added (email={notify_result['email_sent']}, whatsapp={notify_result['whatsapp_sent']})",
        )
    return redirect('task_history', pk=task.id)


@never_cache
@admin_or_manager_required
def task_attachment_upload(request, pk):
    task = get_object_or_404(Task, id=pk)
    if request.method != 'POST':
        return redirect('task_history', pk=task.id)
    form = TaskAttachmentForm(request.POST, request.FILES)
    if form.is_valid():
        attachment = form.save(commit=False)
        attachment.task = task
        attachment.uploaded_by_user = request.user
        attachment.uploaded_by_staff = Staff.objects.filter(user=request.user).first()
        if not attachment.title.strip():
            attachment.title = attachment.file.name
        attachment.save()
        _log_task_activity(
            task,
            TaskActivityLog.ACTION_UPDATED,
            request=request,
            old_status=task.status,
            new_status=task.status,
            note=f'Attachment uploaded: {attachment.title}',
        )
    return redirect('task_history', pk=task.id)


@staff_required
def staff_task_history(request, pk):
    staff = get_object_or_404(Staff, user=request.user)
    task = get_object_or_404(
        Task.objects.select_related('assigned_to'),
        id=pk,
        assigned_to=staff,
    )
    updates = _build_history_updates(task)
    activity_logs = task.activity_logs.select_related('changed_by_user', 'changed_by_staff').all()[:20]
    comments, attachments = _build_task_collaboration(task)
    latest_update = updates[0] if updates else None
    first_update = updates[-1] if updates else None
    return render(
        request,
        'adminpanel/staff_task_history.html',
        {
            'staff': staff,
            'task': task,
            'updates': updates,
            'updates_count': len(updates),
            'latest_update': latest_update,
            'first_update': first_update,
            'is_updated_today': bool(
                latest_update and latest_update.report_date == date.today()
            ),
            'activity_logs': activity_logs,
            'comments': comments,
            'attachments': attachments,
            'comment_form': TaskCommentForm(),
            'attachment_form': TaskAttachmentForm(),
        },
    )


@never_cache
@staff_required
def staff_task_comment_create(request, pk):
    staff = get_object_or_404(Staff, user=request.user)
    task = get_object_or_404(Task, id=pk, assigned_to=staff)
    if request.method != 'POST':
        return redirect('staff_task_history', pk=task.id)
    form = TaskCommentForm(request.POST)
    if form.is_valid():
        parent = None
        parent_id = form.cleaned_data.get('parent_id')
        if parent_id:
            parent = TaskComment.objects.filter(id=parent_id, task=task).first()
        comment = form.save(commit=False)
        comment.task = task
        comment.parent = parent
        comment.user = request.user
        comment.staff = staff
        comment.save()
        notify_result = _notify_task_mentions(
            task,
            comment.text,
            actor_name=staff.name,
        )
        _log_task_activity(
            task,
            TaskActivityLog.ACTION_UPDATED,
            request=request,
            old_status=task.status,
            new_status=task.status,
            note=f"Staff comment added (email={notify_result['email_sent']}, whatsapp={notify_result['whatsapp_sent']})",
        )
    return redirect('staff_task_history', pk=task.id)


@never_cache
@staff_required
def staff_task_attachment_upload(request, pk):
    staff = get_object_or_404(Staff, user=request.user)
    task = get_object_or_404(Task, id=pk, assigned_to=staff)
    if request.method != 'POST':
        return redirect('staff_task_history', pk=task.id)
    form = TaskAttachmentForm(request.POST, request.FILES)
    if form.is_valid():
        attachment = form.save(commit=False)
        attachment.task = task
        attachment.uploaded_by_staff = staff
        attachment.uploaded_by_user = request.user
        if not attachment.title.strip():
            attachment.title = attachment.file.name
        attachment.save()
        _log_task_activity(
            task,
            TaskActivityLog.ACTION_UPDATED,
            request=request,
            old_status=task.status,
            new_status=task.status,
            note=f'Staff uploaded attachment: {attachment.title}',
        )
    return redirect('staff_task_history', pk=task.id)


@never_cache
@staff_required
def staff_task_update(request, pk):
    staff = get_object_or_404(Staff, user=request.user)
    task = get_object_or_404(Task, id=pk, assigned_to=staff)
    latest_daily_update = (
        TaskDailyUpdate.objects.filter(task=task)
        .order_by('-report_date', '-id')
        .first()
    )
    if latest_daily_update:
        latest_daily_update.display_text = _clean_report_text(latest_daily_update.report_text)
    previous_values = {
        'status': task.status,
        'day_report': task.day_report,
    }
    form = StaffTaskUpdateForm(request.POST or None, instance=task)
    if form.is_valid():
        updated_task = form.save()
        changed_fields = []

        if previous_values['status'] != updated_task.status:
            changed_fields.append('Status')
        if previous_values['day_report'] != updated_task.day_report:
            changed_fields.append('Day To Day Report')

        report_text = updated_task.day_report.strip()
        if changed_fields or report_text:
            today = date.today()
            todays_update = (
                TaskDailyUpdate.objects.filter(task=updated_task, report_date=today)
                .order_by('-id')
                .first()
            )
            if not report_text:
                return redirect('staff_my_tasks')

            if todays_update:
                todays_update.project_topic = updated_task.project.name if updated_task.project else updated_task.project_topic
                todays_update.status = updated_task.status
                todays_update.report_text = report_text
                todays_update.save(update_fields=['project_topic', 'status', 'report_text'])
            else:
                TaskDailyUpdate.objects.create(
                    task=updated_task,
                    project_topic=updated_task.project.name if updated_task.project else updated_task.project_topic,
                    status=updated_task.status,
                    report_text=report_text,
                    report_date=today,
                )
        if previous_values['status'] != updated_task.status:
            _log_task_activity(
                updated_task,
                TaskActivityLog.ACTION_STATUS_CHANGED,
                request=request,
                old_status=previous_values['status'],
                new_status=updated_task.status,
                note='Updated by staff from staff task update page',
            )
        if report_text:
            _notify_task_mentions(
                updated_task,
                report_text,
                actor_name=staff.name,
            )
            _log_task_activity(
                updated_task,
                TaskActivityLog.ACTION_DAILY_UPDATE,
                request=request,
                old_status=previous_values['status'],
                new_status=updated_task.status,
                note='Day-to-day report updated by staff',
            )
        return redirect('staff_my_tasks')

    return render(
        request,
        'adminpanel/staff_task_form.html',
        {
            'staff': staff,
            'task': task,
            'form': form,
            'latest_daily_update': latest_daily_update,
            'today': date.today(),
        },
    )
