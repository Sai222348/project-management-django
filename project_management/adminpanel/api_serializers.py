from rest_framework import serializers

from .models import Task, TaskDailyUpdate


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
