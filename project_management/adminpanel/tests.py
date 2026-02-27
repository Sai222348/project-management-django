from datetime import date, timedelta

from django.contrib.auth.models import Group
from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

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
    StaffTimesheetEntry,
    SystemSetting,
    Task,
    TaskAttachment,
    TaskComment,
    TaskActivityLog,
    TaskDailyUpdate,
)


class LoginFlowTests(TestCase):
    def setUp(self):
        self.admin_user = User.objects.create_user(
            username='admin',
            password='Admin@123',
            is_staff=True,
        )
        self.staff_user = User.objects.create_user(
            username='staff1',
            password='Staff@123',
        )
        self.staff = Staff.objects.create(
            name='Staff One',
            email='staff1@example.com',
            role='Developer',
            reporting_officer='Manager',
            user=self.staff_user,
        )

    def test_admin_login_redirects_to_dashboard(self):
        response = self.client.post(
            reverse('admin_login'),
            {'username': 'admin', 'password': 'Admin@123'},
        )
        self.assertRedirects(response, reverse('dashboard'))

    def test_staff_login_redirects_to_staff_dashboard(self):
        response = self.client.post(
            reverse('staff_login'),
            {'username': 'staff1', 'password': 'Staff@123'},
        )
        self.assertRedirects(response, reverse('staff_dashboard'))


class StaffAndTaskFlowTests(TestCase):
    def setUp(self):
        self.admin_user = User.objects.create_user(
            username='admin',
            password='Admin@123',
            is_staff=True,
        )
        self.client.login(username='admin', password='Admin@123')

    def test_admin_can_create_staff_and_linked_user(self):
        response = self.client.post(
            reverse('staff_create'),
            {
                'name': 'New Staff',
                'email': 'new.staff@example.com',
                'role': 'QA',
                'reporting_officer': 'Lead',
                'availability_status': Staff.AVAILABILITY_AVAILABLE,
                'additional_details': 'Handles QA tasks',
                'username': 'newstaff',
                'password': 'NewStaff@123',
            },
        )
        self.assertRedirects(response, reverse('staff'))
        self.assertTrue(Staff.objects.filter(email='new.staff@example.com').exists())
        self.assertTrue(User.objects.filter(username='newstaff').exists())

    def test_admin_can_create_task_and_staff_can_update(self):
        staff_user = User.objects.create_user(username='staff2', password='Staff2@123')
        staff = Staff.objects.create(
            name='Staff Two',
            email='staff2@example.com',
            role='Developer',
            reporting_officer='Manager',
            user=staff_user,
        )
        project = Project.objects.create(
            name='Core Module',
            client='Internal',
            priority=Project.PRIORITY_MEDIUM,
            status=Project.STATUS_ACTIVE,
        )

        create_response = self.client.post(
            reverse('task_create'),
            {
                'title': 'Initial Task',
                'project': project.id,
                'assigned_to': staff.id,
                'start_date': '2026-02-10',
                'due_date': '2026-02-20',
                'day_report': 'Initial report',
            },
        )
        self.assertRedirects(create_response, reverse('tasks'))

        task = Task.objects.get(title='Initial Task')
        self.assertEqual(task.project, project)
        self.assertEqual(task.project_topic, 'Core Module')
        self.assertEqual(task.status, Task.STATUS_PENDING)
        self.assertEqual(task.daily_updates.count(), 1)
        self.assertEqual(task.daily_updates.first().report_date.isoformat(), '2026-02-10')

        self.client.logout()
        self.client.login(username='staff2', password='Staff2@123')

        update_response = self.client.post(
            reverse('staff_task_update', args=[task.id]),
            {
                'status': Task.STATUS_IN_PROGRESS,
                'day_report': 'Work started',
            },
        )
        self.assertRedirects(update_response, reverse('staff_my_tasks'))

        task.refresh_from_db()
        self.assertEqual(task.project_topic, 'Core Module')
        self.assertEqual(task.status, Task.STATUS_IN_PROGRESS)
        self.assertEqual(task.day_report, 'Work started')
        self.assertEqual(TaskDailyUpdate.objects.filter(task=task).count(), 2)
        self.assertTrue(
            TaskDailyUpdate.objects.filter(
                task=task,
                status=Task.STATUS_IN_PROGRESS,
                report_text__icontains='Work started',
            ).exists()
        )

        second_update_response = self.client.post(
            reverse('staff_task_update', args=[task.id]),
            {
                'project_topic': 'Core Module Updated',
                'status': Task.STATUS_COMPLETED,
                'day_report': 'Deployment validation done',
            },
        )
        self.assertRedirects(second_update_response, reverse('staff_my_tasks'))
        self.assertEqual(TaskDailyUpdate.objects.filter(task=task).count(), 2)
        self.assertTrue(
            TaskDailyUpdate.objects.filter(
                task=task,
                status=Task.STATUS_COMPLETED,
                report_text__icontains='Deployment validation done',
            ).exists()
        )

        history_response = self.client.get(reverse('staff_task_history', args=[task.id]))
        self.assertEqual(history_response.status_code, 200)
        self.assertContains(history_response, 'Day To Day Update History')

        self.client.logout()
        self.client.login(username='admin', password='Admin@123')
        admin_history_response = self.client.get(reverse('task_history', args=[task.id]))
        self.assertEqual(admin_history_response.status_code, 200)
        self.assertContains(admin_history_response, 'Task History')

    def test_task_list_supports_search_and_multi_filter(self):
        staff_one = Staff.objects.create(
            name='Filter Staff One',
            email='filter1@example.com',
            role='Developer',
            reporting_officer='Lead',
        )
        staff_two = Staff.objects.create(
            name='Filter Staff Two',
            email='filter2@example.com',
            role='QA',
            reporting_officer='Lead',
        )
        project = Project.objects.create(name='Filter Project')
        Task.objects.create(
            title='Match Me',
            project=project,
            project_topic=project.name,
            assigned_to=staff_one,
            status=Task.STATUS_PENDING,
            start_date='2026-02-10',
            due_date='2026-02-20',
        )
        Task.objects.create(
            title='Do Not Match',
            project=project,
            project_topic=project.name,
            assigned_to=staff_two,
            status=Task.STATUS_COMPLETED,
            start_date='2026-02-11',
            due_date='2026-02-22',
        )

        response = self.client.get(
            reverse('tasks'),
            {
                'q': 'Match',
                'status': Task.STATUS_PENDING,
                'due_date': '2026-02-20',
                'staff': str(staff_one.id),
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Match Me')
        self.assertNotContains(response, 'Do Not Match')

    def test_task_list_bulk_actions_mark_complete_and_reassign(self):
        staff_one = Staff.objects.create(
            name='Bulk Staff One',
            email='bulk1@example.com',
            role='Developer',
            reporting_officer='Lead',
        )
        staff_two = Staff.objects.create(
            name='Bulk Staff Two',
            email='bulk2@example.com',
            role='Developer',
            reporting_officer='Lead',
        )
        project = Project.objects.create(name='Bulk Project')
        task_one = Task.objects.create(
            title='Bulk Task One',
            project=project,
            project_topic=project.name,
            assigned_to=staff_one,
            status=Task.STATUS_PENDING,
            start_date='2026-02-10',
            due_date='2026-02-20',
        )
        task_two = Task.objects.create(
            title='Bulk Task Two',
            project=project,
            project_topic=project.name,
            assigned_to=staff_one,
            status=Task.STATUS_IN_PROGRESS,
            start_date='2026-02-11',
            due_date='2026-02-21',
        )

        mark_response = self.client.post(
            reverse('tasks'),
            {
                'bulk_action': 'mark_complete',
                'task_ids': [str(task_one.id), str(task_two.id)],
            },
            follow=True,
        )
        self.assertEqual(mark_response.status_code, 200)
        self.assertContains(mark_response, 'task(s) marked as completed')
        task_one.refresh_from_db()
        task_two.refresh_from_db()
        self.assertEqual(task_one.status, Task.STATUS_COMPLETED)
        self.assertEqual(task_two.status, Task.STATUS_COMPLETED)

        reassign_response = self.client.post(
            reverse('tasks'),
            {
                'bulk_action': 'reassign',
                'reassign_to': str(staff_two.id),
                'task_ids': [str(task_one.id), str(task_two.id)],
            },
            follow=True,
        )
        self.assertEqual(reassign_response.status_code, 200)
        self.assertContains(reassign_response, 'task(s) reassigned')
        task_one.refresh_from_db()
        task_two.refresh_from_db()
        self.assertEqual(task_one.assigned_to, staff_two)
        self.assertEqual(task_two.assigned_to, staff_two)

    def test_admin_cannot_assign_task_to_unavailable_staff(self):
        unavailable_staff = Staff.objects.create(
            name='Unavailable Staff',
            email='unavailable@example.com',
            role='Developer',
            reporting_officer='Lead',
            availability_status=Staff.AVAILABILITY_ON_LEAVE,
        )
        project = Project.objects.create(name='Availability Project')

        response = self.client.post(
            reverse('task_create'),
            {
                'title': 'Blocked Assignment Task',
                'project': project.id,
                'assigned_to': unavailable_staff.id,
                'start_date': '2026-02-10',
                'due_date': '2026-02-20',
                'day_report': '',
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Select a valid choice.')
        self.assertFalse(Task.objects.filter(title='Blocked Assignment Task').exists())

    def test_staff_workload_page_shows_active_and_overdue_counts(self):
        staff = Staff.objects.create(
            name='Workload Staff',
            email='workload.staff@example.com',
            role='Developer',
            reporting_officer='Lead',
            availability_status=Staff.AVAILABILITY_AVAILABLE,
        )
        project = Project.objects.create(name='Workload Project')
        today = date.today()
        Task.objects.create(
            title='Active Task',
            project=project,
            project_topic=project.name,
            assigned_to=staff,
            status=Task.STATUS_IN_PROGRESS,
            start_date=today - timedelta(days=2),
            due_date=today + timedelta(days=2),
        )
        Task.objects.create(
            title='Overdue Task',
            project=project,
            project_topic=project.name,
            assigned_to=staff,
            status=Task.STATUS_PENDING,
            start_date=today - timedelta(days=4),
            due_date=today - timedelta(days=1),
        )
        Task.objects.create(
            title='Completed Task',
            project=project,
            project_topic=project.name,
            assigned_to=staff,
            status=Task.STATUS_COMPLETED,
            start_date=today - timedelta(days=6),
            due_date=today - timedelta(days=2),
        )

        response = self.client.get(reverse('staff_workload'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Staff Workload')
        self.assertContains(response, 'Workload Staff')
        self.assertContains(response, '<td>2</td>', html=True)
        self.assertContains(response, '<td class="text-danger fw-semibold">1</td>', html=True)


class StaffMyTasksModuleTests(TestCase):
    def setUp(self):
        self.staff_user = User.objects.create_user(
            username='mytasks_staff',
            password='Staff@123',
        )
        self.other_user = User.objects.create_user(
            username='other_staff',
            password='Staff@123',
        )
        self.staff = Staff.objects.create(
            name='My Tasks Staff',
            email='mytasks.staff@example.com',
            role='Developer',
            reporting_officer='Lead',
            user=self.staff_user,
        )
        self.other_staff = Staff.objects.create(
            name='Other Staff',
            email='other.mytasks@example.com',
            role='Developer',
            reporting_officer='Lead',
            user=self.other_user,
        )
        self.project = Project.objects.create(name='My Tasks Project')
        today = date.today()
        self.pending_task = Task.objects.create(
            title='Pending Task',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_PENDING,
            start_date=today - timedelta(days=2),
            due_date=today + timedelta(days=2),
        )
        self.in_progress_task = Task.objects.create(
            title='In Progress Task',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_IN_PROGRESS,
            start_date=today - timedelta(days=3),
            due_date=today + timedelta(days=1),
        )
        self.completed_task = Task.objects.create(
            title='Completed Task',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_COMPLETED,
            start_date=today - timedelta(days=5),
            due_date=today - timedelta(days=1),
        )
        self.other_task = Task.objects.create(
            title='Other Staff Private Task',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.other_staff,
            status=Task.STATUS_PENDING,
            start_date=today - timedelta(days=1),
            due_date=today + timedelta(days=4),
        )

    def test_staff_my_tasks_tabs_filter_correctly(self):
        self.client.login(username='mytasks_staff', password='Staff@123')

        all_response = self.client.get(reverse('staff_my_tasks'))
        self.assertEqual(all_response.status_code, 200)
        self.assertContains(all_response, 'Pending Task')
        self.assertContains(all_response, 'In Progress Task')
        self.assertContains(all_response, 'Completed Task')
        self.assertNotContains(all_response, 'Other Staff Private Task')

        pending_response = self.client.get(reverse('staff_my_tasks'), {'tab': 'pending'})
        self.assertEqual(pending_response.status_code, 200)
        self.assertContains(pending_response, 'Pending Task')
        self.assertNotContains(pending_response, 'In Progress Task')
        self.assertNotContains(pending_response, 'Completed Task')

        in_progress_response = self.client.get(reverse('staff_my_tasks'), {'tab': 'in-progress'})
        self.assertEqual(in_progress_response.status_code, 200)
        self.assertContains(in_progress_response, 'In Progress Task')
        self.assertNotContains(in_progress_response, 'Pending Task')
        self.assertNotContains(in_progress_response, 'Completed Task')

        completed_response = self.client.get(reverse('staff_my_tasks'), {'tab': 'completed'})
        self.assertEqual(completed_response.status_code, 200)
        self.assertContains(completed_response, 'Completed Task')
        self.assertNotContains(completed_response, 'Pending Task')
        self.assertNotContains(completed_response, 'In Progress Task')

    def test_staff_task_detail_is_restricted_to_assigned_staff(self):
        self.client.login(username='mytasks_staff', password='Staff@123')
        own_response = self.client.get(reverse('staff_task_detail', args=[self.pending_task.id]))
        self.assertEqual(own_response.status_code, 200)
        self.assertContains(own_response, 'Task Detail')
        self.assertContains(own_response, 'Pending Task')

        other_response = self.client.get(reverse('staff_task_detail', args=[self.other_task.id]))
        self.assertEqual(other_response.status_code, 404)


class ReportModuleTests(TestCase):
    def setUp(self):
        self.admin_user = User.objects.create_user(
            username='admin',
            password='Admin@123',
            is_staff=True,
        )
        self.client.login(username='admin', password='Admin@123')

        self.staff_1 = Staff.objects.create(
            name='Staff One',
            email='staff.one@example.com',
            role='Developer',
            reporting_officer='Lead',
        )
        self.staff_2 = Staff.objects.create(
            name='Staff Two',
            email='staff.two@example.com',
            role='Tester',
            reporting_officer='Lead',
        )
        self.project = Project.objects.create(name='Report Project')

        today = date.today()
        Task.objects.create(
            title='Completed Task',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff_1,
            status=Task.STATUS_COMPLETED,
            start_date=today - timedelta(days=5),
            due_date=today - timedelta(days=1),
        )
        Task.objects.create(
            title='Overdue Task',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff_1,
            status=Task.STATUS_IN_PROGRESS,
            start_date=today - timedelta(days=7),
            due_date=today - timedelta(days=2),
        )
        Task.objects.create(
            title='Future Task',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff_2,
            status=Task.STATUS_PENDING,
            start_date=today,
            due_date=today + timedelta(days=4),
        )

    def test_reports_dashboard_page_and_csv_export(self):
        page_response = self.client.get(reverse('reports_dashboard'))
        self.assertEqual(page_response.status_code, 200)
        self.assertContains(page_response, 'Reports Dashboard')

        csv_response = self.client.get(reverse('reports_dashboard'), {'format': 'csv'})
        self.assertEqual(csv_response.status_code, 200)
        self.assertEqual(csv_response['Content-Type'], 'text/csv')
        self.assertIn('attachment; filename="reports_dashboard.csv"', csv_response['Content-Disposition'])

    def test_staff_performance_report_filters_and_pdf_export(self):
        page_response = self.client.get(
            reverse('staff_performance_report'),
            {'staff': self.staff_1.id},
        )
        self.assertEqual(page_response.status_code, 200)
        self.assertContains(page_response, 'Staff Performance Report')
        self.assertContains(page_response, '<td>Staff One</td>', html=True)
        self.assertNotContains(page_response, '<td>Staff Two</td>', html=True)

        pdf_response = self.client.get(reverse('staff_performance_report'), {'format': 'pdf'})
        self.assertEqual(pdf_response.status_code, 200)
        self.assertEqual(pdf_response['Content-Type'], 'application/pdf')
        self.assertTrue(pdf_response.content.startswith(b'%PDF'))

    def test_overdue_tasks_report_page_and_csv_export(self):
        page_response = self.client.get(reverse('overdue_tasks_report'))
        self.assertEqual(page_response.status_code, 200)
        self.assertContains(page_response, 'Overdue Tasks Report')
        self.assertContains(page_response, 'Overdue Task')
        self.assertNotContains(page_response, 'Future Task')

        csv_response = self.client.get(reverse('overdue_tasks_report'), {'format': 'csv'})
        self.assertEqual(csv_response.status_code, 200)
        self.assertEqual(csv_response['Content-Type'], 'text/csv')
        self.assertIn('attachment; filename="overdue_tasks_report.csv"', csv_response['Content-Disposition'])


class NotificationModuleTests(TestCase):
    def setUp(self):
        self.admin_user = User.objects.create_user(
            username='admin',
            password='Admin@123',
            is_staff=True,
        )
        self.staff_user = User.objects.create_user(
            username='staff_notify',
            password='Staff@123',
        )
        self.staff = Staff.objects.create(
            name='Notify Staff',
            email='notify.staff@example.com',
            role='Developer',
            reporting_officer='Manager',
            user=self.staff_user,
        )
        self.other_staff = Staff.objects.create(
            name='Other Staff',
            email='other.staff@example.com',
            role='Tester',
            reporting_officer='Manager',
        )
        self.project = Project.objects.create(name='Notify Project')
        today = date.today()

        Task.objects.create(
            title='Admin Due Tomorrow',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_PENDING,
            start_date=today,
            due_date=today + timedelta(days=1),
        )
        Task.objects.create(
            title='Admin Overdue',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.other_staff,
            status=Task.STATUS_IN_PROGRESS,
            start_date=today - timedelta(days=4),
            due_date=today - timedelta(days=1),
        )
        Task.objects.create(
            title='Staff Due Tomorrow',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_IN_PROGRESS,
            start_date=today - timedelta(days=2),
            due_date=today + timedelta(days=1),
        )
        Task.objects.create(
            title='Staff Overdue',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_PENDING,
            start_date=today - timedelta(days=3),
            due_date=today - timedelta(days=1),
        )
        Task.objects.create(
            title='Completed Overdue Should Ignore',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_COMPLETED,
            start_date=today - timedelta(days=5),
            due_date=today - timedelta(days=2),
        )

    def test_admin_dashboard_shows_due_tomorrow_and_overdue_alerts(self):
        self.client.login(username='admin', password='Admin@123')
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Due Tomorrow Reminder')
        self.assertContains(response, 'Overdue Alerts')
        self.assertContains(response, 'Admin Due Tomorrow')
        self.assertContains(response, 'Admin Overdue')

    def test_staff_dashboard_shows_only_staff_notifications(self):
        self.client.login(username='staff_notify', password='Staff@123')
        response = self.client.get(reverse('staff_dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Due Tomorrow Reminder')
        self.assertContains(response, 'Overdue Alerts')
        self.assertContains(response, 'Staff Due Tomorrow')
        self.assertContains(response, 'Staff Overdue')
        self.assertNotContains(response, 'Admin Overdue')
        self.assertEqual(response.context['due_tomorrow_count'], 2)
        self.assertEqual(response.context['overdue_count'], 1)
        overdue_titles = [task.title for task in response.context['overdue_tasks']]
        self.assertNotIn('Completed Overdue Should Ignore', overdue_titles)


class AuthSecurityTests(TestCase):
    def setUp(self):
        self.admin_user = User.objects.create_user(
            username='admin',
            password='Admin@123',
            is_staff=True,
            email='admin@example.com',
        )
        self.manager_user = User.objects.create_user(
            username='manager1',
            password='Manager@123',
            email='manager@example.com',
        )
        manager_group, _ = Group.objects.get_or_create(name='Manager')
        self.manager_user.groups.add(manager_group)
        self.manager_staff = Staff.objects.create(
            name='Manager One',
            email='manager@example.com',
            role='Manager',
            reporting_officer='Director',
            user=self.manager_user,
        )
        self.staff_user = User.objects.create_user(
            username='staffplain',
            password='Staff@123',
            email='staffplain@example.com',
        )
        self.staff_member = Staff.objects.create(
            name='Staff Plain',
            email='staffplain@example.com',
            role='Staff',
            reporting_officer='Manager One',
            user=self.staff_user,
        )

    def test_password_reset_pages_and_request(self):
        response = self.client.get(reverse('password_reset'))
        self.assertEqual(response.status_code, 200)
        post_response = self.client.post(
            reverse('password_reset'),
            {'email': 'staffplain@example.com'},
        )
        self.assertRedirects(post_response, reverse('password_reset_done'))

    def test_manager_role_permissions(self):
        self.client.login(username='manager1', password='Manager@123')
        dashboard_response = self.client.get(reverse('dashboard'))
        self.assertEqual(dashboard_response.status_code, 200)

        task_list_response = self.client.get(reverse('tasks'))
        self.assertEqual(task_list_response.status_code, 200)

        staff_create_response = self.client.get(reverse('staff_create'))
        self.assertEqual(staff_create_response.status_code, 302)
        self.assertIn(reverse('admin_login'), staff_create_response.url)

    def test_staff_cannot_access_admin_dashboard(self):
        self.client.login(username='staffplain', password='Staff@123')
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('admin_login'), response.url)

    def test_login_audit_logs_success_and_failure(self):
        failed_response = self.client.post(
            reverse('staff_login'),
            {'username': 'staffplain', 'password': 'WrongPass'},
        )
        self.assertEqual(failed_response.status_code, 200)
        self.assertTrue(LoginAudit.objects.filter(
            attempted_username='staffplain',
            login_type=LoginAudit.LOGIN_TYPE_STAFF,
            is_success=False,
        ).exists())

        success_response = self.client.post(
            reverse('staff_login'),
            {'username': 'staffplain', 'password': 'Staff@123'},
        )
        self.assertEqual(success_response.status_code, 302)
        self.assertTrue(LoginAudit.objects.filter(
            attempted_username='staffplain',
            login_type=LoginAudit.LOGIN_TYPE_STAFF,
            is_success=True,
        ).exists())

    def test_manager_can_view_login_audit_trail(self):
        LoginAudit.objects.create(
            attempted_username='someone',
            login_type=LoginAudit.LOGIN_TYPE_ADMIN,
            is_success=False,
            failure_reason='bad credentials',
        )
        self.client.login(username='manager1', password='Manager@123')
        response = self.client.get(reverse('login_audit_trail'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Login Audit Trail')

    def test_login_audit_trail_supports_pdf_export(self):
        LoginAudit.objects.create(
            attempted_username='pdfuser',
            login_type=LoginAudit.LOGIN_TYPE_STAFF,
            is_success=True,
        )
        self.client.login(username='manager1', password='Manager@123')
        response = self.client.get(reverse('login_audit_trail'), {'format': 'pdf'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertTrue(response.content.startswith(b'%PDF'))

    def test_task_activity_log_created_for_admin_and_staff_updates(self):
        staff_user = User.objects.create_user(username='act_staff', password='Staff@123')
        staff = Staff.objects.create(
            name='Activity Staff',
            email='activity.staff@example.com',
            role='Developer',
            reporting_officer='Manager',
            user=staff_user,
        )
        project = Project.objects.create(name='Activity Project')
        self.client.login(username='admin', password='Admin@123')
        create_response = self.client.post(
            reverse('task_create'),
            {
                'title': 'Activity Task',
                'project': project.id,
                'assigned_to': staff.id,
                'start_date': '2026-02-10',
                'due_date': '2026-02-20',
                'day_report': '',
            },
        )
        self.assertEqual(create_response.status_code, 302)
        task = Task.objects.get(title='Activity Task')
        self.assertTrue(TaskActivityLog.objects.filter(task=task, action=TaskActivityLog.ACTION_CREATED).exists())

        self.client.logout()
        self.client.login(username='act_staff', password='Staff@123')
        staff_update_response = self.client.post(
            reverse('staff_task_update', args=[task.id]),
            {
                'status': Task.STATUS_IN_PROGRESS,
                'day_report': 'Work started',
            },
        )
        self.assertEqual(staff_update_response.status_code, 302)
        self.assertTrue(
            TaskActivityLog.objects.filter(
                task=task,
                action=TaskActivityLog.ACTION_STATUS_CHANGED,
                changed_by_staff=staff,
                new_status=Task.STATUS_IN_PROGRESS,
            ).exists()
        )

    def test_activity_log_page_admin_only(self):
        self.client.login(username='admin', password='Admin@123')
        response = self.client.get(reverse('activity_log'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Task Activity Log')

        self.client.logout()
        self.client.login(username='manager1', password='Manager@123')
        manager_response = self.client.get(reverse('activity_log'))
        self.assertEqual(manager_response.status_code, 302)
        self.assertIn(reverse('admin_login'), manager_response.url)

    def test_system_settings_page_admin_only_and_save(self):
        self.client.login(username='admin', password='Admin@123')
        response = self.client.post(
            reverse('system_settings'),
            {
                'company_name': 'Acme PM',
                'working_days': 'Mon,Tue,Wed,Thu,Fri',
                'reminder_time': '10:30',
                'support_email': 'support@acme.test',
                'support_phone': '+1-555-0100',
            },
        )
        self.assertEqual(response.status_code, 302)
        setting = SystemSetting.objects.get(id=1)
        self.assertEqual(setting.company_name, 'Acme PM')
        self.assertEqual(setting.support_email, 'support@acme.test')

        self.client.logout()
        self.client.login(username='manager1', password='Manager@123')
        manager_response = self.client.get(reverse('system_settings'))
        self.assertEqual(manager_response.status_code, 302)
        self.assertIn(reverse('admin_login'), manager_response.url)

    def test_custom_404_page_shows_support_contact(self):
        SystemSetting.objects.update_or_create(
            id=1,
            defaults={
                'company_name': 'Acme PM',
                'support_email': 'help@acme.test',
                'support_phone': '+1-555-0200',
            },
        )
        response = self.client.get('/this-page-does-not-exist/')
        self.assertEqual(response.status_code, 404)
        self.assertContains(response, 'Acme PM', status_code=404)
        self.assertContains(response, 'help@acme.test', status_code=404)
        self.assertContains(response, '+1-555-0200', status_code=404)


class ExpandedCoverageTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(
            username='adminx',
            password='Admin@123',
            is_staff=True,
        )
        self.manager_user = User.objects.create_user(
            username='managerx',
            password='Manager@123',
        )
        manager_group, _ = Group.objects.get_or_create(name='Manager')
        self.manager_user.groups.add(manager_group)
        self.manager_staff = Staff.objects.create(
            name='Manager X',
            email='managerx@example.com',
            role='Manager',
            reporting_officer='Director',
            user=self.manager_user,
        )
        self.staff_user = User.objects.create_user(
            username='staffx',
            password='Staff@123',
        )
        self.staff = Staff.objects.create(
            name='Staff X',
            email='staffx@example.com',
            role='Developer',
            reporting_officer='Manager X',
            user=self.staff_user,
        )
        self.other_staff = Staff.objects.create(
            name='Other Staff',
            email='otherstaff@example.com',
            role='Developer',
            reporting_officer='Manager X',
        )
        self.project = Project.objects.create(name='Coverage Project')
        today = date.today()
        self.overdue_pending = Task.objects.create(
            title='Overdue Pending',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_PENDING,
            start_date=today - timedelta(days=6),
            due_date=today - timedelta(days=1),
        )
        self.overdue_completed = Task.objects.create(
            title='Overdue Completed',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_COMPLETED,
            start_date=today - timedelta(days=6),
            due_date=today - timedelta(days=1),
        )
        self.future_task = Task.objects.create(
            title='Future Task X',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.other_staff,
            status=Task.STATUS_IN_PROGRESS,
            start_date=today,
            due_date=today + timedelta(days=2),
        )

    def test_permissions_unauthenticated_redirects_for_protected_pages(self):
        for route in ['dashboard', 'tasks', 'reports_dashboard', 'activity_log']:
            response = self.client.get(reverse(route))
            self.assertEqual(response.status_code, 302)
            self.assertIn(reverse('admin_login'), response.url)

    def test_permissions_staff_cannot_access_admin_manager_pages(self):
        self.client.login(username='staffx', password='Staff@123')
        for route in ['tasks', 'reports_dashboard', 'overdue_tasks_report', 'activity_log']:
            response = self.client.get(reverse(route))
            self.assertEqual(response.status_code, 302)
            self.assertIn(reverse('admin_login'), response.url)

    def test_negative_bulk_actions_no_selection_and_invalid_action(self):
        self.client.login(username='adminx', password='Admin@123')
        no_selection = self.client.post(
            reverse('tasks'),
            {'bulk_action': 'mark_complete'},
            follow=True,
        )
        self.assertEqual(no_selection.status_code, 200)
        self.assertContains(no_selection, 'Please select at least one task.')

        invalid_action = self.client.post(
            reverse('tasks'),
            {'bulk_action': 'bad_action', 'task_ids': [str(self.overdue_pending.id)]},
            follow=True,
        )
        self.assertEqual(invalid_action.status_code, 200)
        self.assertContains(invalid_action, 'Please choose a valid bulk action.')

    def test_overdue_logic_excludes_completed_and_respects_filters(self):
        self.client.login(username='adminx', password='Admin@123')
        response = self.client.get(reverse('overdue_tasks_report'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Overdue Pending')
        self.assertNotContains(response, 'Overdue Completed')
        self.assertNotContains(response, 'Future Task X')

        filtered = self.client.get(
            reverse('overdue_tasks_report'),
            {
                'staff': str(self.other_staff.id),
                'status': Task.STATUS_IN_PROGRESS,
            },
        )
        self.assertEqual(filtered.status_code, 200)
        self.assertNotContains(filtered, 'Overdue Pending')

    def test_report_filters_date_range_and_status(self):
        self.client.login(username='adminx', password='Admin@123')
        today = date.today().isoformat()
        response = self.client.get(
            reverse('reports_dashboard'),
            {
                'status': Task.STATUS_IN_PROGRESS,
                'date_from': today,
                'date_to': (date.today() + timedelta(days=3)).isoformat(),
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Future Task X')
        self.assertNotContains(response, 'Overdue Pending')


class APIModuleTests(TestCase):
    def setUp(self):
        self.client_api = APIClient()
        self.admin = User.objects.create_user(
            username='apiadmin',
            password='Admin@123',
            is_staff=True,
        )
        self.manager = User.objects.create_user(username='apimanager', password='Manager@123')
        manager_group, _ = Group.objects.get_or_create(name='Manager')
        self.manager.groups.add(manager_group)
        self.staff_user = User.objects.create_user(username='apistaff', password='Staff@123')
        self.other_user = User.objects.create_user(username='apiother', password='Staff@123')

        self.staff = Staff.objects.create(
            name='API Staff',
            email='api.staff@example.com',
            role='Developer',
            reporting_officer='Lead',
            user=self.staff_user,
        )
        self.other_staff = Staff.objects.create(
            name='API Other',
            email='api.other@example.com',
            role='Developer',
            reporting_officer='Lead',
            user=self.other_user,
        )
        self.project = Project.objects.create(name='API Project')
        today = date.today()
        self.own_task = Task.objects.create(
            title='Own API Task',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_PENDING,
            start_date=today - timedelta(days=2),
            due_date=today + timedelta(days=1),
        )
        self.other_task = Task.objects.create(
            title='Other API Task',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.other_staff,
            status=Task.STATUS_IN_PROGRESS,
            start_date=today - timedelta(days=3),
            due_date=today - timedelta(days=1),
        )

    def test_api_token_endpoint_returns_token(self):
        response = self.client_api.post(
            '/api/auth/token/',
            {'username': 'apistaff', 'password': 'Staff@123'},
            format='json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.data)

    def test_staff_task_api_returns_only_own_tasks(self):
        self.client_api.force_authenticate(user=self.staff_user)
        response = self.client_api.get('/api/tasks/')
        self.assertEqual(response.status_code, 200)
        titles = [row['title'] for row in response.data]
        self.assertIn('Own API Task', titles)
        self.assertNotIn('Other API Task', titles)

    def test_staff_can_create_update_for_own_task_only(self):
        self.client_api.force_authenticate(user=self.staff_user)
        allowed = self.client_api.post(
            '/api/updates/',
            {
                'task': self.own_task.id,
                'status': Task.STATUS_IN_PROGRESS,
                'report_text': 'Started via API',
            },
            format='json',
        )
        self.assertEqual(allowed.status_code, 201)
        self.assertTrue(TaskDailyUpdate.objects.filter(task=self.own_task).exists())

        forbidden = self.client_api.post(
            '/api/updates/',
            {
                'task': self.other_task.id,
                'status': Task.STATUS_IN_PROGRESS,
                'report_text': 'Should fail',
            },
            format='json',
        )
        self.assertEqual(forbidden.status_code, 403)

    def test_admin_can_create_task_via_api(self):
        self.client_api.force_authenticate(user=self.admin)
        response = self.client_api.post(
            '/api/tasks/',
            {
                'title': 'Created Through API',
                'project': self.project.id,
                'assigned_to': self.staff.id,
                'start_date': date.today().isoformat(),
                'due_date': (date.today() + timedelta(days=3)).isoformat(),
                'day_report': '',
            },
            format='json',
        )
        self.assertEqual(response.status_code, 201)
        self.assertTrue(Task.objects.filter(title='Created Through API').exists())

    def test_reports_api_supports_filters_and_overdue(self):
        self.client_api.force_authenticate(user=self.admin)
        summary = self.client_api.get('/api/reports/summary/', {'status': Task.STATUS_IN_PROGRESS})
        self.assertEqual(summary.status_code, 200)
        self.assertGreaterEqual(summary.data['total_tasks'], 1)

        overdue = self.client_api.get('/api/reports/overdue/')
        self.assertEqual(overdue.status_code, 200)
        overdue_titles = [row['title'] for row in overdue.data]
        self.assertIn('Other API Task', overdue_titles)


class StaffProfileModuleTests(TestCase):
    def setUp(self):
        self.staff_user = User.objects.create_user(
            username='profile_staff',
            password='Staff@123',
            email='profile.staff@example.com',
        )
        self.staff = Staff.objects.create(
            name='Profile Staff',
            email='profile.staff@example.com',
            contact_number='1234567890',
            role='Developer',
            reporting_officer='Lead Manager',
            user=self.staff_user,
        )
        self.admin = User.objects.create_user(
            username='profile_admin',
            password='Admin@123',
            is_staff=True,
        )

    def test_staff_profile_page_shows_profile_fields(self):
        self.client.login(username='profile_staff', password='Staff@123')
        response = self.client.get(reverse('staff_profile'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Profile Staff')
        self.assertContains(response, '1234567890')
        self.assertContains(response, 'Lead Manager')

    def test_staff_profile_edit_updates_contact_and_email(self):
        self.client.login(username='profile_staff', password='Staff@123')
        response = self.client.post(
            reverse('staff_profile_edit'),
            {
                'name': 'Profile Staff Updated',
                'email': 'profile.staff.updated@example.com',
                'contact_number': '9999999999',
                'role': 'Hacker',
                'reporting_officer': 'Another Manager',
            },
        )
        self.assertEqual(response.status_code, 302)
        self.staff.refresh_from_db()
        self.staff_user.refresh_from_db()
        self.assertEqual(self.staff.name, 'Profile Staff Updated')
        self.assertEqual(self.staff.email, 'profile.staff.updated@example.com')
        self.assertEqual(self.staff.contact_number, '9999999999')
        self.assertEqual(self.staff.role, 'Developer')
        self.assertEqual(self.staff.reporting_officer, 'Lead Manager')
        self.assertEqual(self.staff_user.email, 'profile.staff.updated@example.com')

    def test_staff_change_password_works(self):
        self.client.login(username='profile_staff', password='Staff@123')
        response = self.client.post(
            reverse('staff_change_password'),
            {
                'old_password': 'Staff@123',
                'new_password1': 'NewStaff@12345',
                'new_password2': 'NewStaff@12345',
            },
        )
        self.assertEqual(response.status_code, 302)
        self.client.logout()
        login_ok = self.client.login(username='profile_staff', password='NewStaff@12345')
        self.assertTrue(login_ok)

    def test_admin_cannot_access_staff_profile_pages(self):
        self.client.login(username='profile_admin', password='Admin@123')
        for route_name in ['staff_profile', 'staff_profile_edit', 'staff_change_password']:
            response = self.client.get(reverse(route_name))
            self.assertEqual(response.status_code, 302)
            self.assertIn(reverse('staff_login'), response.url)


class StaffNotificationSettingsModuleTests(TestCase):
    def setUp(self):
        self.staff_user = User.objects.create_user(
            username='notif_staff',
            password='Staff@123',
        )
        self.staff = Staff.objects.create(
            name='Notif Staff',
            email='notif.staff@example.com',
            role='Developer',
            reporting_officer='Lead',
            user=self.staff_user,
        )
        self.admin_user = User.objects.create_user(
            username='notif_admin',
            password='Admin@123',
            is_staff=True,
        )
        self.project = Project.objects.create(name='Notif Module Project')
        today = date.today()
        self.due_tomorrow_task = Task.objects.create(
            title='Due Tomorrow Task',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_PENDING,
            start_date=today - timedelta(days=1),
            due_date=today + timedelta(days=1),
        )
        self.overdue_task = Task.objects.create(
            title='Overdue Task',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_IN_PROGRESS,
            start_date=today - timedelta(days=4),
            due_date=today - timedelta(days=1),
        )
        TaskDailyUpdate.objects.create(
            task=self.due_tomorrow_task,
            status=Task.STATUS_PENDING,
            report_text='Need review from @notif_staff',
            report_date=today,
        )

    def test_staff_notifications_page_shows_due_overdue_and_mentions(self):
        self.client.login(username='notif_staff', password='Staff@123')
        response = self.client.get(reverse('staff_notifications'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Notifications')
        self.assertContains(response, 'Due Tomorrow Task')
        self.assertContains(response, 'Overdue Task')
        self.assertContains(response, 'Need review from @notif_staff')

    def test_staff_can_update_notification_settings(self):
        self.client.login(username='notif_staff', password='Staff@123')
        response = self.client.post(
            reverse('staff_notification_settings'),
            {
                'overdue_enabled': 'on',
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        setting = StaffNotificationSetting.objects.get(staff=self.staff)
        self.assertFalse(setting.email_reminders)
        self.assertFalse(setting.in_app_reminders)
        self.assertFalse(setting.due_tomorrow_enabled)
        self.assertTrue(setting.overdue_enabled)
        self.assertFalse(setting.mention_enabled)

        notifications_response = self.client.get(reverse('staff_notifications'))
        self.assertContains(notifications_response, 'In-app reminders are currently turned off.')

    def test_admin_cannot_access_staff_notification_pages(self):
        self.client.login(username='notif_admin', password='Admin@123')
        for route_name in ['staff_notifications', 'staff_notification_settings']:
            response = self.client.get(reverse(route_name))
            self.assertEqual(response.status_code, 302)
            self.assertIn(reverse('staff_login'), response.url)


class StaffAttendanceLeaveModuleTests(TestCase):
    def setUp(self):
        self.staff_user = User.objects.create_user(
            username='attendance_staff',
            password='Staff@123',
        )
        self.staff = Staff.objects.create(
            name='Attendance Staff',
            email='attendance.staff@example.com',
            role='Developer',
            reporting_officer='Lead',
            user=self.staff_user,
        )
        self.admin_user = User.objects.create_user(
            username='attendance_admin',
            password='Admin@123',
            is_staff=True,
        )

    def test_staff_attendance_create_and_update(self):
        self.client.login(username='attendance_staff', password='Staff@123')
        response = self.client.post(
            reverse('staff_attendance'),
            {
                'attendance_date': date.today().isoformat(),
                'check_in': '09:30',
                'check_out': '18:00',
                'status': 'Present',
                'note': 'Worked from office',
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            StaffAttendance.objects.filter(
                staff=self.staff,
                attendance_date=date.today(),
                status='Present',
            ).exists()
        )
        self.assertContains(response, 'Worked from office')

    def test_staff_can_apply_leave_and_view_history_and_calendar(self):
        self.client.login(username='attendance_staff', password='Staff@123')
        apply_response = self.client.post(
            reverse('staff_apply_leave'),
            {
                'start_date': date.today().isoformat(),
                'end_date': (date.today() + timedelta(days=1)).isoformat(),
                'reason': 'Medical leave',
            },
            follow=True,
        )
        self.assertEqual(apply_response.status_code, 200)
        self.assertTrue(
            StaffLeaveRequest.objects.filter(
                staff=self.staff,
                reason='Medical leave',
                status=StaffLeaveRequest.STATUS_PENDING,
            ).exists()
        )
        history_response = self.client.get(reverse('staff_leave_history'))
        self.assertEqual(history_response.status_code, 200)
        self.assertContains(history_response, 'Medical leave')

        calendar_response = self.client.get(reverse('staff_availability_calendar'))
        self.assertEqual(calendar_response.status_code, 200)
        self.assertContains(calendar_response, 'Staff Availability Calendar')

    def test_admin_cannot_access_staff_attendance_leave_pages(self):
        self.client.login(username='attendance_admin', password='Admin@123')
        for route_name in [
            'staff_attendance',
            'staff_apply_leave',
            'staff_leave_history',
            'staff_availability_calendar',
        ]:
            response = self.client.get(reverse(route_name))
            self.assertEqual(response.status_code, 302)
            self.assertIn(reverse('staff_login'), response.url)


class StaffAdvancedModulesTests(TestCase):
    def setUp(self):
        self.staff_user = User.objects.create_user(
            username='advanced_staff',
            password='Staff@123',
        )
        self.staff = Staff.objects.create(
            name='Advanced Staff',
            email='advanced.staff@example.com',
            role='Developer',
            reporting_officer='Lead',
            user=self.staff_user,
        )
        self.project = Project.objects.create(name='Advanced Project')
        self.task = Task.objects.create(
            title='Advanced Task',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_IN_PROGRESS,
            start_date=date.today() - timedelta(days=2),
            due_date=date.today() + timedelta(days=3),
        )

    def test_timesheet_and_worklog_pages(self):
        self.client.login(username='advanced_staff', password='Staff@123')
        response = self.client.post(
            reverse('staff_timesheet_daily'),
            {
                'work_date': date.today().isoformat(),
                'task': self.task.id,
                'hours_spent': '4.50',
                'work_summary': 'Implemented API endpoints',
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(StaffTimesheetEntry.objects.filter(staff=self.staff, task=self.task).exists())

        weekly = self.client.get(reverse('staff_timesheet_weekly'))
        self.assertEqual(weekly.status_code, 200)
        self.assertContains(weekly, 'Weekly Timesheet')

        history = self.client.get(reverse('staff_worklog_history'))
        self.assertEqual(history.status_code, 200)
        self.assertContains(history, 'Implemented API endpoints')

    def test_performance_goal_documents_and_helpdesk_pages(self):
        self.client.login(username='advanced_staff', password='Staff@123')
        StaffTimesheetEntry.objects.create(
            staff=self.staff,
            task=self.task,
            work_date=date.today(),
            hours_spent='2.00',
            work_summary='Quick fix',
        )
        Task.objects.filter(id=self.task.id).update(status=Task.STATUS_COMPLETED)

        perf = self.client.get(reverse('staff_performance_dashboard'))
        self.assertEqual(perf.status_code, 200)
        self.assertContains(perf, 'Performance Dashboard')

        goal_response = self.client.post(
            reverse('staff_goal_tracker'),
            {
                'title': 'Complete Sprint Tasks',
                'target_value': 10,
                'current_value': 3,
                'start_date': date.today().isoformat(),
                'end_date': (date.today() + timedelta(days=10)).isoformat(),
                'status': StaffGoal.STATUS_ACTIVE,
                'note': 'Week 1 target',
            },
            follow=True,
        )
        self.assertEqual(goal_response.status_code, 200)
        self.assertTrue(StaffGoal.objects.filter(staff=self.staff, title='Complete Sprint Tasks').exists())

        upload = SimpleUploadedFile('policy.txt', b'policy content', content_type='text/plain')
        doc_response = self.client.post(
            reverse('staff_document_upload'),
            {
                'title': 'Sprint Policy',
                'category': StaffDocument.CATEGORY_POLICY,
                'task': '',
                'file': upload,
            },
            follow=True,
        )
        self.assertEqual(doc_response.status_code, 200)
        self.assertTrue(StaffDocument.objects.filter(staff=self.staff, title='Sprint Policy').exists())

        docs_page = self.client.get(reverse('staff_documents'))
        self.assertEqual(docs_page.status_code, 200)
        self.assertContains(docs_page, 'Sprint Policy')

        ticket_response = self.client.post(
            reverse('staff_helpdesk_create_ticket'),
            {
                'subject': 'Need VPN Access',
                'description': 'Unable to connect to VPN',
                'priority': HelpdeskTicket.PRIORITY_HIGH,
            },
            follow=True,
        )
        self.assertEqual(ticket_response.status_code, 200)
        self.assertTrue(HelpdeskTicket.objects.filter(staff=self.staff, subject='Need VPN Access').exists())

        faq_page = self.client.get(reverse('staff_faq'))
        self.assertEqual(faq_page.status_code, 200)
        self.assertContains(faq_page, 'FAQ')


class StaffMeApiTests(TestCase):
    def setUp(self):
        self.client_api = APIClient()
        self.staff_user = User.objects.create_user(username='me_api_staff', password='Staff@123')
        self.staff = Staff.objects.create(
            name='Me API Staff',
            email='me.api.staff@example.com',
            role='Developer',
            reporting_officer='Lead',
            user=self.staff_user,
        )
        self.project = Project.objects.create(name='Me API Project')
        self.task = Task.objects.create(
            title='API Personal Task',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_PENDING,
            start_date=date.today() - timedelta(days=1),
            due_date=date.today() + timedelta(days=1),
        )
        StaffTimesheetEntry.objects.create(
            staff=self.staff,
            task=self.task,
            work_date=date.today(),
            hours_spent='5.00',
            work_summary='Daily coding',
        )

    def test_my_tasks_and_daily_update_and_notifications_and_performance_api(self):
        self.client_api.force_authenticate(user=self.staff_user)

        my_tasks = self.client_api.get('/api/me/my-tasks/')
        self.assertEqual(my_tasks.status_code, 200)
        self.assertEqual(len(my_tasks.data), 1)
        self.assertEqual(my_tasks.data[0]['title'], 'API Personal Task')

        daily_update = self.client_api.post(
            '/api/me/daily-update/',
            {
                'task': self.task.id,
                'status': Task.STATUS_IN_PROGRESS,
                'report_text': 'Progress update via me api',
            },
            format='json',
        )
        self.assertEqual(daily_update.status_code, 201)
        self.task.refresh_from_db()
        self.assertEqual(self.task.status, Task.STATUS_IN_PROGRESS)

        notifications = self.client_api.get('/api/me/my-notifications/')
        self.assertEqual(notifications.status_code, 200)
        self.assertIn('due_tomorrow_count', notifications.data)

        performance = self.client_api.get('/api/me/my-performance/')
        self.assertEqual(performance.status_code, 200)
        self.assertIn('completed_tasks', performance.data)
        self.assertIn('productivity_score', performance.data)


class CoverageExtensionTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(
            username='cov_admin',
            password='Admin@123',
            is_staff=True,
        )
        self.manager = User.objects.create_user(
            username='cov_manager',
            password='Manager@123',
        )
        manager_group, _ = Group.objects.get_or_create(name='Manager')
        self.manager.groups.add(manager_group)

        self.staff_user = User.objects.create_user(
            username='cov_staff_user',
            password='Staff@123',
        )
        self.staff = Staff.objects.create(
            name='Coverage Staff',
            email='coverage.staff@example.com',
            role='Developer',
            reporting_officer='Lead',
            user=self.staff_user,
        )
        self.project = Project.objects.create(name='Coverage Project')
        self.task = Task.objects.create(
            title='Coverage Task',
            project=self.project,
            project_topic=self.project.name,
            assigned_to=self.staff,
            status=Task.STATUS_PENDING,
            start_date=date.today(),
            due_date=date.today() + timedelta(days=2),
        )

    def test_manager_cannot_perform_task_mutations(self):
        self.client.login(username='cov_manager', password='Manager@123')

        create_get = self.client.get(reverse('task_create'))
        self.assertEqual(create_get.status_code, 302)

        update_get = self.client.get(reverse('task_update', args=[self.task.id]))
        self.assertEqual(update_get.status_code, 302)

        bulk_post = self.client.post(
            reverse('tasks'),
            {'bulk_action': 'mark_complete', 'task_ids': [str(self.task.id)]},
        )
        self.assertEqual(bulk_post.status_code, 403)
        self.assertIn('403 Forbidden', bulk_post.content.decode())

    def test_invalid_task_date_is_rejected(self):
        self.client.login(username='cov_admin', password='Admin@123')
        response = self.client.post(
            reverse('task_create'),
            {
                'title': 'Bad Date Task',
                'project': self.project.id,
                'assigned_to': self.staff.id,
                'start_date': '2026-02-20',
                'due_date': '2026-02-10',
                'day_report': '',
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Due date cannot be earlier than start date.')
        self.assertFalse(Task.objects.filter(title='Bad Date Task').exists())

    def test_duplicate_staff_email_is_rejected(self):
        self.client.login(username='cov_admin', password='Admin@123')
        response = self.client.post(
            reverse('staff_create'),
            {
                'name': 'Duplicate Email Staff',
                'email': 'coverage.staff@example.com',
                'role': 'Developer',
                'reporting_officer': 'Lead',
                'availability_status': Staff.AVAILABILITY_AVAILABLE,
                'username': 'coverage_dup',
                'password': 'Coverage@123',
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'This email is already in use.')

    def test_custom_404_page_is_rendered(self):
        response = self.client.get('/path-that-does-not-exist/')
        self.assertEqual(response.status_code, 404)
        self.assertIn('404 Not Found', response.content.decode())

    def test_task_comment_create_and_attachment_validation(self):
        self.client.login(username='cov_staff_user', password='Staff@123')
        comment_response = self.client.post(
            reverse('staff_task_comment_create', args=[self.task.id]),
            {'text': 'Checking comment mention @cov_admin'},
        )
        self.assertEqual(comment_response.status_code, 302)
        self.assertTrue(TaskComment.objects.filter(task=self.task, text__icontains='Checking comment').exists())

        bad_file = SimpleUploadedFile('malware.exe', b'12345', content_type='application/octet-stream')
        attach_response = self.client.post(
            reverse('staff_task_attachment_upload', args=[self.task.id]),
            {'title': 'Bad file', 'file': bad_file},
            follow=True,
        )
        self.assertEqual(attach_response.status_code, 200)
        self.assertFalse(TaskAttachment.objects.filter(task=self.task, title='Bad file').exists())

    def test_reports_support_xlsx_export(self):
        self.client.login(username='cov_admin', password='Admin@123')
        response = self.client.get(reverse('reports_dashboard'), {'format': 'xlsx'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' in response['Content-Type']
            or 'text/csv' in response['Content-Type']
        )

    def test_log_retention_purge_command(self):
        self.client.login(username='cov_admin', password='Admin@123')
        log = TaskActivityLog.objects.create(
            task=self.task,
            action=TaskActivityLog.ACTION_UPDATED,
            old_status=self.task.status,
            new_status=self.task.status,
            changed_by_user=self.admin,
            note='old log',
        )
        old_timestamp = timezone.now() - timedelta(days=400)
        TaskActivityLog.objects.filter(id=log.id).update(created_at=old_timestamp)

        call_command('purge_old_logs', days=180)
        self.assertFalse(TaskActivityLog.objects.filter(id=log.id).exists())
