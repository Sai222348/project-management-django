from datetime import date, timedelta

from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from django.utils.dateparse import parse_date
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView

from .api_serializers import TaskDailyUpdateSerializer, TaskSerializer
from .models import Staff, StaffTimesheetEntry, Task, TaskActivityLog, TaskDailyUpdate


def _is_admin_or_manager(user):
    return user.is_authenticated and (
        user.is_superuser
        or user.is_staff
        or user.groups.filter(name__in=['Admin', 'Manager']).exists()
    )


def _get_staff_profile(user):
    if not user or not user.is_authenticated:
        return None
    return Staff.objects.filter(user=user).first()


def _apply_task_filters(queryset, params):
    status_value = (params.get('status') or '').strip()
    staff_value = (params.get('staff') or '').strip()
    due_from = parse_date((params.get('due_from') or '').strip()) if params.get('due_from') else None
    due_to = parse_date((params.get('due_to') or '').strip()) if params.get('due_to') else None
    overdue = (params.get('overdue') or '').strip().lower()

    if status_value in {choice[0] for choice in Task.STATUS_CHOICES}:
        queryset = queryset.filter(status=status_value)
    if staff_value.isdigit():
        queryset = queryset.filter(assigned_to_id=int(staff_value))
    if due_from:
        queryset = queryset.filter(due_date__gte=due_from)
    if due_to:
        queryset = queryset.filter(due_date__lte=due_to)
    if overdue == 'true':
        queryset = queryset.filter(due_date__lt=date.today()).exclude(status=Task.STATUS_COMPLETED)
    return queryset


def _staff_only_or_forbidden(user):
    staff = _get_staff_profile(user)
    if not staff:
        return None
    return staff


class TaskViewSet(viewsets.ModelViewSet):
    serializer_class = TaskSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = Task.objects.select_related('assigned_to', 'project').order_by('-id')
        if _is_admin_or_manager(self.request.user):
            return _apply_task_filters(qs, self.request.query_params)

        staff = _get_staff_profile(self.request.user)
        if not staff:
            return Task.objects.none()
        return _apply_task_filters(qs.filter(assigned_to=staff), self.request.query_params)

    def create(self, request, *args, **kwargs):
        if not _is_admin_or_manager(request.user):
            return Response({'detail': 'Only admin/manager can create tasks.'}, status=status.HTTP_403_FORBIDDEN)
        return super().create(request, *args, **kwargs)

    def perform_create(self, serializer):
        task = serializer.save()
        if task.project:
            task.project_topic = task.project.name
            task.save(update_fields=['project_topic'])
        TaskActivityLog.objects.create(
            task=task,
            action=TaskActivityLog.ACTION_CREATED,
            old_status='',
            new_status=task.status,
            changed_by_user=self.request.user,
            changed_by_staff=_get_staff_profile(self.request.user),
            note='Created via API',
        )

    def update(self, request, *args, **kwargs):
        task = self.get_object()
        if not _is_admin_or_manager(request.user):
            staff = _get_staff_profile(request.user)
            if not staff or task.assigned_to_id != staff.id:
                return Response({'detail': 'Not allowed.'}, status=status.HTTP_403_FORBIDDEN)
            disallowed = {'assigned_to', 'project', 'project_topic', 'start_date', 'due_date', 'title'}
            if any(field in request.data for field in disallowed):
                return Response(
                    {'detail': 'Staff can only update status/day_report via API.'},
                    status=status.HTTP_403_FORBIDDEN,
                )
        return super().update(request, *args, **kwargs)

    def perform_update(self, serializer):
        task = self.get_object()
        old_status = task.status
        updated_task = serializer.save()
        if updated_task.project:
            updated_task.project_topic = updated_task.project.name
            updated_task.save(update_fields=['project_topic'])

        if old_status != updated_task.status:
            TaskActivityLog.objects.create(
                task=updated_task,
                action=TaskActivityLog.ACTION_STATUS_CHANGED,
                old_status=old_status,
                new_status=updated_task.status,
                changed_by_user=self.request.user,
                changed_by_staff=_get_staff_profile(self.request.user),
                note='Updated via API',
            )

    def destroy(self, request, *args, **kwargs):
        if not _is_admin_or_manager(request.user):
            return Response({'detail': 'Only admin/manager can delete tasks.'}, status=status.HTTP_403_FORBIDDEN)
        return super().destroy(request, *args, **kwargs)


class TaskDailyUpdateViewSet(viewsets.ModelViewSet):
    serializer_class = TaskDailyUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = TaskDailyUpdate.objects.select_related('task', 'task__assigned_to').order_by('-report_date', '-id')
        if _is_admin_or_manager(self.request.user):
            return qs
        staff = _get_staff_profile(self.request.user)
        if not staff:
            return TaskDailyUpdate.objects.none()
        return qs.filter(task__assigned_to=staff)

    def create(self, request, *args, **kwargs):
        task_id = request.data.get('task')
        task = get_object_or_404(Task, id=task_id)
        if not _is_admin_or_manager(request.user):
            staff = _get_staff_profile(request.user)
            if not staff or task.assigned_to_id != staff.id:
                return Response({'detail': 'You can only add updates to your tasks.'}, status=status.HTTP_403_FORBIDDEN)

        report_text = (request.data.get('report_text') or '').strip()
        if not report_text:
            return Response({'detail': 'report_text is required.'}, status=status.HTTP_400_BAD_REQUEST)

        status_value = request.data.get('status') or task.status
        if status_value not in {choice[0] for choice in Task.STATUS_CHOICES}:
            return Response({'detail': 'Invalid status.'}, status=status.HTTP_400_BAD_REQUEST)

        old_status = task.status
        report_date_raw = request.data.get('report_date')
        report_date = parse_date(report_date_raw) if report_date_raw else date.today()
        update = TaskDailyUpdate.objects.create(
            task=task,
            project_topic=task.project.name if task.project else task.project_topic,
            status=status_value,
            report_text=report_text,
            report_date=report_date,
        )
        task.status = status_value
        task.day_report = report_text
        task.save(update_fields=['status', 'day_report'])

        TaskActivityLog.objects.create(
            task=task,
            action=TaskActivityLog.ACTION_DAILY_UPDATE,
            old_status=old_status,
            new_status=status_value,
            changed_by_user=request.user,
            changed_by_staff=_get_staff_profile(request.user),
            note='Daily update via API',
        )

        serializer = self.get_serializer(update)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ReportsSummaryAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        tasks = _apply_task_filters(Task.objects.all(), request.query_params)
        if not _is_admin_or_manager(request.user):
            staff = _get_staff_profile(request.user)
            tasks = tasks.filter(assigned_to=staff) if staff else Task.objects.none()

        total = tasks.count()
        completed = tasks.filter(status=Task.STATUS_COMPLETED).count()
        in_progress = tasks.filter(status=Task.STATUS_IN_PROGRESS).count()
        pending = tasks.filter(status=Task.STATUS_PENDING).count()
        overdue = tasks.filter(due_date__lt=date.today()).exclude(status=Task.STATUS_COMPLETED).count()
        completion_rate = round((completed / total) * 100) if total else 0
        return Response(
            {
                'total_tasks': total,
                'completed': completed,
                'in_progress': in_progress,
                'pending': pending,
                'overdue': overdue,
                'completion_rate': completion_rate,
            }
        )


class ReportsStaffPerformanceAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        tasks = _apply_task_filters(Task.objects.all(), request.query_params)
        if not _is_admin_or_manager(request.user):
            staff = _get_staff_profile(request.user)
            tasks = tasks.filter(assigned_to=staff) if staff else Task.objects.none()

        today = date.today()
        rows = list(
            tasks.values('assigned_to_id', 'assigned_to__name')
            .annotate(
                total_tasks=Count('id'),
                completed_tasks=Count('id', filter=Q(status=Task.STATUS_COMPLETED)),
                in_progress_tasks=Count('id', filter=Q(status=Task.STATUS_IN_PROGRESS)),
                pending_tasks=Count('id', filter=Q(status=Task.STATUS_PENDING)),
                overdue_tasks=Count('id', filter=Q(due_date__lt=today) & ~Q(status=Task.STATUS_COMPLETED)),
            )
            .order_by('assigned_to__name')
        )
        return Response(rows)


class ReportsOverdueAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        tasks = _apply_task_filters(Task.objects.select_related('assigned_to', 'project'), request.query_params)
        if not _is_admin_or_manager(request.user):
            staff = _get_staff_profile(request.user)
            tasks = tasks.filter(assigned_to=staff) if staff else Task.objects.none()

        overdue = tasks.filter(due_date__lt=date.today()).exclude(status=Task.STATUS_COMPLETED)
        payload = [
            {
                'id': task.id,
                'title': task.title,
                'project': task.project.name if task.project else (task.project_topic or ''),
                'assigned_to': task.assigned_to.name,
                'status': task.status,
                'start_date': task.start_date,
                'due_date': task.due_date,
            }
            for task in overdue
        ]
        return Response(payload)


class MyTasksAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        staff = _staff_only_or_forbidden(request.user)
        if not staff:
            return Response({'detail': 'Staff profile required.'}, status=status.HTTP_403_FORBIDDEN)
        tasks = Task.objects.filter(assigned_to=staff).select_related('project').order_by('due_date', '-id')
        status_filter = (request.query_params.get('status') or '').strip()
        if status_filter in {choice[0] for choice in Task.STATUS_CHOICES}:
            tasks = tasks.filter(status=status_filter)
        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data)


class MyDailyUpdateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        staff = _staff_only_or_forbidden(request.user)
        if not staff:
            return Response({'detail': 'Staff profile required.'}, status=status.HTTP_403_FORBIDDEN)
        updates = TaskDailyUpdate.objects.filter(task__assigned_to=staff).order_by('-report_date', '-id')
        serializer = TaskDailyUpdateSerializer(updates, many=True)
        return Response(serializer.data)

    def post(self, request):
        staff = _staff_only_or_forbidden(request.user)
        if not staff:
            return Response({'detail': 'Staff profile required.'}, status=status.HTTP_403_FORBIDDEN)
        task_id = request.data.get('task')
        task = get_object_or_404(Task, id=task_id, assigned_to=staff)

        report_text = (request.data.get('report_text') or '').strip()
        if not report_text:
            return Response({'detail': 'report_text is required.'}, status=status.HTTP_400_BAD_REQUEST)

        status_value = request.data.get('status') or task.status
        if status_value not in {choice[0] for choice in Task.STATUS_CHOICES}:
            return Response({'detail': 'Invalid status.'}, status=status.HTTP_400_BAD_REQUEST)

        old_status = task.status
        report_date_raw = request.data.get('report_date')
        report_date = parse_date(report_date_raw) if report_date_raw else date.today()
        update = TaskDailyUpdate.objects.create(
            task=task,
            project_topic=task.project.name if task.project else task.project_topic,
            status=status_value,
            report_text=report_text,
            report_date=report_date,
        )
        task.status = status_value
        task.day_report = report_text
        task.save(update_fields=['status', 'day_report'])
        TaskActivityLog.objects.create(
            task=task,
            action=TaskActivityLog.ACTION_DAILY_UPDATE,
            old_status=old_status,
            new_status=status_value,
            changed_by_user=request.user,
            changed_by_staff=staff,
            note='Daily update via My Daily Update API',
        )
        serializer = TaskDailyUpdateSerializer(update)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class MyNotificationsAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        staff = _staff_only_or_forbidden(request.user)
        if not staff:
            return Response({'detail': 'Staff profile required.'}, status=status.HTTP_403_FORBIDDEN)

        today = date.today()
        tasks = Task.objects.filter(assigned_to=staff).exclude(status=Task.STATUS_COMPLETED)
        due_tomorrow = tasks.filter(due_date=today + timedelta(days=1)).order_by('due_date', 'id')
        overdue = tasks.filter(due_date__lt=today).order_by('due_date', 'id')
        mention_patterns = []
        if staff.user:
            mention_patterns.append(f"@{staff.user.username.lower()}")
        mention_patterns.append(f"@{staff.name.lower()}")

        mention_updates = []
        for row in TaskDailyUpdate.objects.filter(task__assigned_to=staff).exclude(report_text='').order_by('-created_at')[:100]:
            row_text = (row.report_text or '').lower()
            if any(token in row_text for token in mention_patterns):
                mention_updates.append(
                    {
                        'task': row.task.title,
                        'report_text': row.report_text,
                        'report_date': row.report_date,
                    }
                )

        return Response(
            {
                'due_tomorrow_count': due_tomorrow.count(),
                'overdue_count': overdue.count(),
                'mentions_count': len(mention_updates),
                'due_tomorrow': [{'id': t.id, 'title': t.title, 'due_date': t.due_date} for t in due_tomorrow[:10]],
                'overdue': [{'id': t.id, 'title': t.title, 'due_date': t.due_date} for t in overdue[:10]],
                'mentions': mention_updates[:10],
            }
        )


class MyPerformanceAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        staff = _staff_only_or_forbidden(request.user)
        if not staff:
            return Response({'detail': 'Staff profile required.'}, status=status.HTTP_403_FORBIDDEN)

        today = date.today()
        tasks = Task.objects.filter(assigned_to=staff)
        total_tasks = tasks.count()
        completed_tasks = tasks.filter(status=Task.STATUS_COMPLETED).count()
        overdue_tasks = tasks.filter(due_date__lt=today).exclude(status=Task.STATUS_COMPLETED).count()
        delay_percent = round((overdue_tasks / total_tasks) * 100, 2) if total_tasks else 0
        hours = StaffTimesheetEntry.objects.filter(staff=staff)
        total_logged_hours = round(sum(float(row.hours_spent) for row in hours), 2)
        productivity_score = round((completed_tasks / total_logged_hours) * 100, 2) if total_logged_hours else 0

        return Response(
            {
                'total_tasks': total_tasks,
                'completed_tasks': completed_tasks,
                'overdue_tasks': overdue_tasks,
                'delay_percent': delay_percent,
                'total_logged_hours': total_logged_hours,
                'productivity_score': productivity_score,
            }
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def api_health(request):
    return Response({'status': 'ok', 'service': 'adminpanel-api'})
