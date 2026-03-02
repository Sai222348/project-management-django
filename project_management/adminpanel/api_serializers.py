from rest_framework import serializers

from .models import Project, Staff, Task, TaskAttachment, TaskComment, TaskDailyUpdate


class ProjectSerializer(serializers.ModelSerializer):
    task_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Project
        fields = [
            'id',
            'name',
            'client',
            'start_date',
            'end_date',
            'priority',
            'status',
            'task_count',
        ]


class StaffSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = Staff
        fields = [
            'id',
            'name',
            'email',
            'contact_number',
            'role',
            'reporting_officer',
            'availability_status',
            'leave_until',
            'username',
        ]


class TaskSerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source='project.name', read_only=True)
    assigned_to_name = serializers.CharField(source='assigned_to.name', read_only=True)

    class Meta:
        model = Task
        fields = [
            'id',
            'title',
            'project',
            'project_name',
            'project_topic',
            'assigned_to',
            'assigned_to_name',
            'status',
            'day_report',
            'start_date',
            'due_date',
        ]


class TaskDailyUpdateSerializer(serializers.ModelSerializer):
    task_title = serializers.CharField(source='task.title', read_only=True)
    updated_by = serializers.SerializerMethodField()

    class Meta:
        model = TaskDailyUpdate
        fields = [
            'id',
            'task',
            'task_title',
            'project_topic',
            'status',
            'report_text',
            'report_date',
            'created_at',
            'updated_by',
        ]
        read_only_fields = ['created_at', 'project_topic', 'status']

    def get_updated_by(self, obj):
        return self.context.get('updated_by', '')


class TaskCommentSerializer(serializers.ModelSerializer):
    task_title = serializers.CharField(source='task.title', read_only=True)
    staff_name = serializers.CharField(source='staff.name', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = TaskComment
        fields = [
            'id',
            'task',
            'task_title',
            'parent',
            'text',
            'staff',
            'staff_name',
            'user',
            'username',
            'created_at',
        ]
        read_only_fields = ['staff', 'user', 'created_at']


class TaskAttachmentSerializer(serializers.ModelSerializer):
    task_title = serializers.CharField(source='task.title', read_only=True)
    uploaded_by_name = serializers.SerializerMethodField()
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = TaskAttachment
        fields = [
            'id',
            'task',
            'task_title',
            'title',
            'file',
            'file_url',
            'uploaded_by_staff',
            'uploaded_by_user',
            'uploaded_by_name',
            'created_at',
        ]
        read_only_fields = ['uploaded_by_staff', 'uploaded_by_user', 'created_at']

    def get_uploaded_by_name(self, obj):
        if obj.uploaded_by_staff:
            return obj.uploaded_by_staff.name
        if obj.uploaded_by_user:
            return obj.uploaded_by_user.username
        return ''

    def get_file_url(self, obj):
        request = self.context.get('request')
        if not obj.file:
            return ''
        if request:
            return request.build_absolute_uri(obj.file.url)
        return obj.file.url
