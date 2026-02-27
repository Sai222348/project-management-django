from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.home, name='home'),

    # AUTH
    path('login/', views.login_selector, name='login'),
    path('login/admin/', views.admin_login_view, name='admin_login'),
    path('login/staff/', views.staff_login_view, name='staff_login'),
    path(
        'password/forgot/',
        auth_views.PasswordResetView.as_view(
            template_name='adminpanel/password_reset_form.html',
            email_template_name='adminpanel/password_reset_email.txt',
            subject_template_name='adminpanel/password_reset_subject.txt',
        ),
        name='password_reset',
    ),
    path(
        'password/forgot/done/',
        auth_views.PasswordResetDoneView.as_view(
            template_name='adminpanel/password_reset_done.html',
        ),
        name='password_reset_done',
    ),
    path(
        'password/reset/<uidb64>/<token>/',
        auth_views.PasswordResetConfirmView.as_view(
            template_name='adminpanel/password_reset_confirm.html',
        ),
        name='password_reset_confirm',
    ),
    path(
        'password/reset/complete/',
        auth_views.PasswordResetCompleteView.as_view(
            template_name='adminpanel/password_reset_complete.html',
        ),
        name='password_reset_complete',
    ),
    path('logout/', views.logout_view, name='logout'),
    path('staff/dashboard/', views.staff_dashboard, name='staff_dashboard'),
    path('staff/my-tasks/', views.staff_task_list, name='staff_my_tasks'),
    path('staff/profile/', views.staff_profile, name='staff_profile'),
    path('staff/profile/edit/', views.staff_profile_edit, name='staff_profile_edit'),
    path('staff/profile/change-password/', views.staff_change_password, name='staff_change_password'),
    path('staff/notifications/', views.staff_notifications, name='staff_notifications'),
    path('staff/notifications/settings/', views.staff_notification_settings, name='staff_notification_settings'),
    path('staff/attendance/', views.staff_attendance, name='staff_attendance'),
    path('staff/leave/apply/', views.staff_apply_leave, name='staff_apply_leave'),
    path('staff/leave/history/', views.staff_leave_history, name='staff_leave_history'),
    path('staff/availability/calendar/', views.staff_availability_calendar, name='staff_availability_calendar'),
    path('staff/timesheet/daily/', views.staff_timesheet_daily, name='staff_timesheet_daily'),
    path('staff/timesheet/weekly/', views.staff_timesheet_weekly, name='staff_timesheet_weekly'),
    path('staff/worklog/history/', views.staff_worklog_history, name='staff_worklog_history'),
    path('staff/performance/', views.staff_performance_dashboard, name='staff_performance_dashboard'),
    path('staff/goals/', views.staff_goal_tracker, name='staff_goal_tracker'),
    path('staff/documents/', views.staff_documents, name='staff_documents'),
    path('staff/documents/upload/', views.staff_document_upload, name='staff_document_upload'),
    path('staff/helpdesk/create/', views.staff_helpdesk_create_ticket, name='staff_helpdesk_create_ticket'),
    path('staff/helpdesk/history/', views.staff_helpdesk_history, name='staff_helpdesk_history'),
    path('staff/faq/', views.staff_faq, name='staff_faq'),
    path('staff/tasks/', views.staff_task_list, name='staff_tasks'),
    path('staff/tasks/<int:pk>/', views.staff_task_detail, name='staff_task_detail'),
    path('staff/tasks/edit/<int:pk>/', views.staff_task_update, name='staff_task_update'),
    path('staff/tasks/history/<int:pk>/', views.staff_task_history, name='staff_task_history'),
    path('staff/tasks/history/<int:pk>/comment/', views.staff_task_comment_create, name='staff_task_comment_create'),
    path('staff/tasks/history/<int:pk>/attachment/', views.staff_task_attachment_upload, name='staff_task_attachment_upload'),

    # DASHBOARD
    path('dashboard/', views.dashboard, name='dashboard'),
    path('security/login-audit/', views.login_audit_trail, name='login_audit_trail'),
    path('system/settings/', views.system_settings, name='system_settings'),
    path('security/activity-log/', views.activity_log, name='activity_log'),

    # REPORTS
    path('reports/', views.reports_dashboard, name='reports_dashboard'),
    path('reports/staff-performance/', views.staff_performance_report, name='staff_performance_report'),
    path('reports/overdue-tasks/', views.overdue_tasks_report, name='overdue_tasks_report'),

    # PROJECTS
    path('projects/', views.project_list, name='projects'),
    path('projects/add/', views.project_create, name='project_create'),
    path('projects/edit/<int:pk>/', views.project_update, name='project_update'),
    path('projects/<int:pk>/', views.project_detail, name='project_detail'),

    # STAFF
    path('staff/', views.staff_list, name='staff'),
    path('staff/view/<int:pk>/', views.staff_detail, name='staff_detail'),
    path('staff/workload/', views.staff_workload, name='staff_workload'),
    path('staff/add/', views.staff_create, name='staff_create'),
    path('staff/edit/<int:pk>/', views.staff_update, name='staff_update'),
    path('staff/delete/<int:pk>/', views.staff_delete, name='staff_delete'),

    # TASKS
    path('tasks/', views.task_list, name='tasks'),
    path('tasks/add/', views.task_create, name='task_create'),
    path('tasks/edit/<int:pk>/', views.task_update, name='task_update'),
    path('tasks/history/<int:pk>/', views.task_history, name='task_history'),
    path('tasks/history/<int:pk>/comment/', views.task_comment_create, name='task_comment_create'),
    path('tasks/history/<int:pk>/attachment/', views.task_attachment_upload, name='task_attachment_upload'),
    path('tasks/delete/<int:pk>/', views.task_delete, name='task_delete'),
]
