from django.contrib import admin
from .models import (
    LoginAudit,
    Project,
    Staff,
    SystemSetting,
    Task,
    TaskActivityLog,
    TaskAttachment,
    TaskComment,
    TaskDailyUpdate,
)

admin.site.register(Project)
admin.site.register(Staff)
admin.site.register(Task)
admin.site.register(TaskDailyUpdate)
admin.site.register(TaskComment)
admin.site.register(TaskAttachment)
admin.site.register(LoginAudit)
admin.site.register(TaskActivityLog)
admin.site.register(SystemSetting)
