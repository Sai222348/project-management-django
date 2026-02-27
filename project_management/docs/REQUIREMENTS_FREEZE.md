# Requirements Freeze (Scope Lock)

Date: 2026-02-19

## Final In-Scope Modules

### Admin Module
- Admin authentication and dashboard
- Staff management: list/view/create/update/delete
- Task management: list/filter, create/update/delete, bulk actions
- Project management: list/create/update/detail
- Reports: dashboard, staff performance, overdue tasks, CSV/PDF export
- System settings and activity/login audit views

### Staff Module
- Staff authentication and dashboard
- My tasks: list/detail/update/history (assigned tasks only)
- Notifications and notification preferences
- Attendance and leave flows
- Profile and password change

### Task Module
- Task CRUD by Admin only
- Staff can update only assigned task status/day report
- Task history with daily updates and activity logs

## Out of Scope (Current Freeze)
- New module additions not listed above
- Workflow redesign beyond current UI/UX structure
- Cross-app refactor outside adminpanel scope

## Permission Lock
- `Admin`: full staff/task CRUD
- `Manager`: read-only for staff/task listings and reports/dashboards
- `Staff`: assigned-task-only access for task detail/update/history

