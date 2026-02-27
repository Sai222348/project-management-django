from django.urls import include, path
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.routers import DefaultRouter

from .api_views import (
    MyDailyUpdateAPIView,
    MyNotificationsAPIView,
    MyPerformanceAPIView,
    MyTasksAPIView,
    ReportsOverdueAPIView,
    ReportsStaffPerformanceAPIView,
    ReportsSummaryAPIView,
    TaskDailyUpdateViewSet,
    TaskViewSet,
    api_health,
)

router = DefaultRouter()
router.register('tasks', TaskViewSet, basename='api-tasks')
router.register('updates', TaskDailyUpdateViewSet, basename='api-updates')

urlpatterns = [
    path('auth/token/', obtain_auth_token, name='api_token_auth'),
    path('health/', api_health, name='api_health'),
    path('reports/summary/', ReportsSummaryAPIView.as_view(), name='api_reports_summary'),
    path('reports/staff-performance/', ReportsStaffPerformanceAPIView.as_view(), name='api_reports_staff_performance'),
    path('reports/overdue/', ReportsOverdueAPIView.as_view(), name='api_reports_overdue'),
    path('me/my-tasks/', MyTasksAPIView.as_view(), name='api_my_tasks'),
    path('me/daily-update/', MyDailyUpdateAPIView.as_view(), name='api_my_daily_update'),
    path('me/my-notifications/', MyNotificationsAPIView.as_view(), name='api_my_notifications'),
    path('me/my-performance/', MyPerformanceAPIView.as_view(), name='api_my_performance'),
    path('', include(router.urls)),
]
