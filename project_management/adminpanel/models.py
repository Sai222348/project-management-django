from datetime import date

from django.db import models
from django.contrib.auth.models import User

class Staff(models.Model):
    ROLE_ADMIN = 'Admin'
    ROLE_MANAGER = 'Manager'
    ROLE_STAFF = 'Staff'

    AVAILABILITY_AVAILABLE = 'Available'
    AVAILABILITY_ON_LEAVE = 'On Leave'
    AVAILABILITY_UNAVAILABLE = 'Unavailable'
    AVAILABILITY_CHOICES = [
        (AVAILABILITY_AVAILABLE, 'Available'),
        (AVAILABILITY_ON_LEAVE, 'On Leave'),
        (AVAILABILITY_UNAVAILABLE, 'Unavailable'),
    ]

    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    contact_number = models.CharField(max_length=20, blank=True)
    role = models.CharField(max_length=100)
    reporting_officer = models.CharField(max_length=100, blank=True)
    availability_status = models.CharField(
        max_length=20,
        choices=AVAILABILITY_CHOICES,
        default=AVAILABILITY_AVAILABLE,
    )
    leave_until = models.DateField(null=True, blank=True)
    additional_details = models.TextField(blank=True)
    user = models.OneToOneField(User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.name

    @property
    def normalized_role(self):
        return (self.role or '').strip().lower()

    @property
    def is_manager_role(self):
        return self.normalized_role == self.ROLE_MANAGER.lower()


class Project(models.Model):
    PRIORITY_LOW = 'Low'
    PRIORITY_MEDIUM = 'Medium'
    PRIORITY_HIGH = 'High'
    PRIORITY_CHOICES = [
        (PRIORITY_LOW, 'Low'),
        (PRIORITY_MEDIUM, 'Medium'),
        (PRIORITY_HIGH, 'High'),
    ]

    STATUS_PLANNED = 'Planned'
    STATUS_ACTIVE = 'Active'
    STATUS_ON_HOLD = 'On Hold'
    STATUS_COMPLETED = 'Completed'
    STATUS_CHOICES = [
        (STATUS_PLANNED, 'Planned'),
        (STATUS_ACTIVE, 'Active'),
        (STATUS_ON_HOLD, 'On Hold'),
        (STATUS_COMPLETED, 'Completed'),
    ]

    name = models.CharField(max_length=200, unique=True)
    client = models.CharField(max_length=200, blank=True)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default=PRIORITY_MEDIUM)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PLANNED)

    def __str__(self):
        return self.name


class Task(models.Model):
    STATUS_PENDING = 'Pending'
    STATUS_IN_PROGRESS = 'In Progress'
    STATUS_COMPLETED = 'Completed'
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_IN_PROGRESS, 'In Progress'),
        (STATUS_COMPLETED, 'Completed'),
    ]

    title = models.CharField(max_length=200)
    project_topic = models.CharField(max_length=200, blank=True)
    project = models.ForeignKey(Project, on_delete=models.SET_NULL, null=True, blank=True, related_name='tasks')
    assigned_to = models.ForeignKey(Staff, on_delete=models.CASCADE)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    day_report = models.TextField(blank=True)
    start_date = models.DateField()
    due_date = models.DateField()

    def __str__(self):
        return self.title


class TaskDailyUpdate(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='daily_updates')
    project_topic = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=20, choices=Task.STATUS_CHOICES, default=Task.STATUS_PENDING)
    report_text = models.TextField(blank=True)
    report_date = models.DateField(default=date.today)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['report_date', 'id']

    def __str__(self):
        return f"{self.task.title} - {self.report_date}"


class TaskComment(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='comments')
    staff = models.ForeignKey(Staff, on_delete=models.SET_NULL, null=True, blank=True, related_name='task_comments')
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='task_comments')
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='replies')
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at', 'id']

    def __str__(self):
        return f"{self.task.title} comment #{self.id}"


class TaskAttachment(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='attachments')
    uploaded_by_staff = models.ForeignKey(
        Staff,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='task_attachments',
    )
    uploaded_by_user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='task_attachments',
    )
    title = models.CharField(max_length=200, blank=True)
    file = models.FileField(upload_to='task_attachments/')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']

    def __str__(self):
        return self.title or self.file.name


class LoginAudit(models.Model):
    LOGIN_TYPE_ADMIN = 'Admin'
    LOGIN_TYPE_STAFF = 'Staff'
    LOGIN_TYPE_CHOICES = [
        (LOGIN_TYPE_ADMIN, 'Admin'),
        (LOGIN_TYPE_STAFF, 'Staff'),
    ]

    attempted_username = models.CharField(max_length=150, blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    login_type = models.CharField(max_length=20, choices=LOGIN_TYPE_CHOICES)
    is_success = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    attempted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-attempted_at', '-id']

    def __str__(self):
        status = 'Success' if self.is_success else 'Failed'
        return f"{self.login_type} login {status} - {self.attempted_username or '-'}"


class TaskActivityLog(models.Model):
    ACTION_CREATED = 'Created'
    ACTION_UPDATED = 'Updated'
    ACTION_STATUS_CHANGED = 'Status Changed'
    ACTION_REASSIGNED = 'Reassigned'
    ACTION_MARKED_COMPLETED = 'Marked Completed'
    ACTION_DAILY_UPDATE = 'Daily Update'
    ACTION_DELETED = 'Deleted'
    ACTION_CHOICES = [
        (ACTION_CREATED, 'Created'),
        (ACTION_UPDATED, 'Updated'),
        (ACTION_STATUS_CHANGED, 'Status Changed'),
        (ACTION_REASSIGNED, 'Reassigned'),
        (ACTION_MARKED_COMPLETED, 'Marked Completed'),
        (ACTION_DAILY_UPDATE, 'Daily Update'),
        (ACTION_DELETED, 'Deleted'),
    ]

    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='activity_logs')
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    old_status = models.CharField(max_length=20, blank=True)
    new_status = models.CharField(max_length=20, blank=True)
    changed_by_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    changed_by_staff = models.ForeignKey(
        Staff,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='activity_logs',
    )
    note = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']

    def __str__(self):
        return f"{self.task.title} - {self.action}"


class SystemSetting(models.Model):
    company_name = models.CharField(max_length=150, default='Project Management')
    working_days = models.CharField(max_length=100, default='Mon,Tue,Wed,Thu,Fri')
    reminder_time = models.TimeField(default='09:00')
    support_email = models.EmailField(default='support@example.com')
    support_phone = models.CharField(max_length=30, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.company_name


class StaffNotificationSetting(models.Model):
    staff = models.OneToOneField(
        Staff,
        on_delete=models.CASCADE,
        related_name='notification_setting',
    )
    email_reminders = models.BooleanField(default=True)
    in_app_reminders = models.BooleanField(default=True)
    due_tomorrow_enabled = models.BooleanField(default=True)
    overdue_enabled = models.BooleanField(default=True)
    mention_enabled = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.staff.name} Notification Settings"


class StaffAttendance(models.Model):
    STATUS_PRESENT = 'Present'
    STATUS_ABSENT = 'Absent'
    STATUS_ON_LEAVE = 'On Leave'
    STATUS_HALF_DAY = 'Half Day'
    STATUS_CHOICES = [
        (STATUS_PRESENT, 'Present'),
        (STATUS_ABSENT, 'Absent'),
        (STATUS_ON_LEAVE, 'On Leave'),
        (STATUS_HALF_DAY, 'Half Day'),
    ]

    staff = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='attendance_records')
    attendance_date = models.DateField(default=date.today)
    check_in = models.TimeField(null=True, blank=True)
    check_out = models.TimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PRESENT)
    note = models.CharField(max_length=255, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-attendance_date', '-id']
        unique_together = ('staff', 'attendance_date')

    def __str__(self):
        return f"{self.staff.name} - {self.attendance_date} ({self.status})"


class StaffLeaveRequest(models.Model):
    STATUS_PENDING = 'Pending'
    STATUS_APPROVED = 'Approved'
    STATUS_REJECTED = 'Rejected'
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_APPROVED, 'Approved'),
        (STATUS_REJECTED, 'Rejected'),
    ]

    staff = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='leave_requests')
    start_date = models.DateField()
    end_date = models.DateField()
    reason = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    applied_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-applied_at', '-id']

    @property
    def total_days(self):
        return (self.end_date - self.start_date).days + 1

    def __str__(self):
        return f"{self.staff.name} leave {self.start_date} to {self.end_date} ({self.status})"


class StaffTimesheetEntry(models.Model):
    staff = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='timesheet_entries')
    task = models.ForeignKey(Task, on_delete=models.SET_NULL, null=True, blank=True, related_name='timesheet_entries')
    work_date = models.DateField(default=date.today)
    hours_spent = models.DecimalField(max_digits=5, decimal_places=2)
    work_summary = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-work_date', '-id']

    def __str__(self):
        return f"{self.staff.name} - {self.work_date} ({self.hours_spent}h)"


class StaffGoal(models.Model):
    STATUS_ACTIVE = 'Active'
    STATUS_COMPLETED = 'Completed'
    STATUS_PAUSED = 'Paused'
    STATUS_CHOICES = [
        (STATUS_ACTIVE, 'Active'),
        (STATUS_COMPLETED, 'Completed'),
        (STATUS_PAUSED, 'Paused'),
    ]

    staff = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='goals')
    title = models.CharField(max_length=200)
    target_value = models.PositiveIntegerField(default=1)
    current_value = models.PositiveIntegerField(default=0)
    start_date = models.DateField(default=date.today)
    end_date = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    note = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at', '-id']

    @property
    def progress_percent(self):
        if not self.target_value:
            return 0
        return min(round((self.current_value / self.target_value) * 100), 100)

    def __str__(self):
        return f"{self.staff.name} - {self.title}"


class StaffDocument(models.Model):
    CATEGORY_TASK_ATTACHMENT = 'Task Attachment'
    CATEGORY_POLICY = 'Policy'
    CATEGORY_TEMPLATE = 'Template'
    CATEGORY_OTHER = 'Other'
    CATEGORY_CHOICES = [
        (CATEGORY_TASK_ATTACHMENT, 'Task Attachment'),
        (CATEGORY_POLICY, 'Policy'),
        (CATEGORY_TEMPLATE, 'Template'),
        (CATEGORY_OTHER, 'Other'),
    ]

    staff = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='documents')
    task = models.ForeignKey(Task, on_delete=models.SET_NULL, null=True, blank=True, related_name='documents')
    title = models.CharField(max_length=200)
    category = models.CharField(max_length=30, choices=CATEGORY_CHOICES, default=CATEGORY_OTHER)
    file = models.FileField(upload_to='staff_documents/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-uploaded_at', '-id']

    def __str__(self):
        return f"{self.title} ({self.staff.name})"


class HelpdeskTicket(models.Model):
    PRIORITY_LOW = 'Low'
    PRIORITY_MEDIUM = 'Medium'
    PRIORITY_HIGH = 'High'
    PRIORITY_CHOICES = [
        (PRIORITY_LOW, 'Low'),
        (PRIORITY_MEDIUM, 'Medium'),
        (PRIORITY_HIGH, 'High'),
    ]

    STATUS_OPEN = 'Open'
    STATUS_IN_PROGRESS = 'In Progress'
    STATUS_RESOLVED = 'Resolved'
    STATUS_CLOSED = 'Closed'
    STATUS_CHOICES = [
        (STATUS_OPEN, 'Open'),
        (STATUS_IN_PROGRESS, 'In Progress'),
        (STATUS_RESOLVED, 'Resolved'),
        (STATUS_CLOSED, 'Closed'),
    ]

    staff = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='helpdesk_tickets')
    subject = models.CharField(max_length=200)
    description = models.TextField()
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default=PRIORITY_MEDIUM)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN)
    response_note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at', '-id']

    def __str__(self):
        return f"{self.staff.name} - {self.subject}"
