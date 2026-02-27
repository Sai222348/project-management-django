from datetime import datetime
import re

from django import forms
from django.contrib.auth.models import User
from django.db.models import Q
from .models import (
    HelpdeskTicket,
    Project,
    Staff,
    StaffAttendance,
    TaskAttachment,
    TaskComment,
    StaffDocument,
    StaffGoal,
    StaffLeaveRequest,
    StaffNotificationSetting,
    StaffTimesheetEntry,
    SystemSetting,
    Task,
)

class StaffForm(forms.ModelForm):
    username = forms.CharField(max_length=150, widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
    )

    class Meta:
        model = Staff
        fields = [
            'name',
            'email',
            'contact_number',
            'role',
            'reporting_officer',
            'availability_status',
            'leave_until',
            'additional_details',
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'contact_number': forms.TextInput(attrs={'class': 'form-control'}),
            'role': forms.TextInput(attrs={'class': 'form-control'}),
            'reporting_officer': forms.TextInput(attrs={'class': 'form-control'}),
            'availability_status': forms.Select(attrs={'class': 'form-select'}),
            'leave_until': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'additional_details': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk and self.instance.user:
            self.fields['username'].initial = self.instance.user.username
            self.fields['password'].help_text = "Leave blank to keep current password."
        else:
            self.fields['password'].required = True
            self.fields['password'].help_text = "Set initial password."

    def clean_username(self):
        username = self.cleaned_data['username']
        qs = User.objects.filter(username=username)
        if self.instance and self.instance.pk and self.instance.user:
            qs = qs.exclude(pk=self.instance.user.pk)
        if qs.exists():
            raise forms.ValidationError("This username is already taken.")
        return username

    def clean_email(self):
        email = (self.cleaned_data.get('email') or '').strip().lower()
        if not email:
            raise forms.ValidationError("Email is required.")
        qs = Staff.objects.filter(email__iexact=email)
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError("This email is already in use.")
        return email


class TaskForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        available_staff = Staff.objects.filter(availability_status=Staff.AVAILABILITY_AVAILABLE)
        if self.instance and self.instance.pk and self.instance.assigned_to_id:
            self.fields['assigned_to'].queryset = Staff.objects.filter(
                Q(pk=self.instance.assigned_to_id)
                | Q(availability_status=Staff.AVAILABILITY_AVAILABLE)
            ).distinct().order_by('name')
        else:
            self.fields['assigned_to'].queryset = available_staff.order_by('name')

    def clean_assigned_to(self):
        assigned_to = self.cleaned_data.get('assigned_to')
        if assigned_to and assigned_to.availability_status != Staff.AVAILABILITY_AVAILABLE:
            raise forms.ValidationError('Selected staff is not available for assignment.')
        return assigned_to

    def clean(self):
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        due_date = cleaned_data.get('due_date')
        if start_date and due_date and due_date < start_date:
            self.add_error('due_date', 'Due date cannot be earlier than start date.')
        return cleaned_data

    class Meta:
        model = Task
        fields = ['title', 'project', 'assigned_to', 'status', 'day_report', 'start_date', 'due_date']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'project': forms.Select(attrs={'class': 'form-select'}),
            'assigned_to': forms.Select(attrs={'class': 'form-select'}),
            'status': forms.Select(attrs={'class': 'form-select'}),
            'day_report': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
            'start_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'due_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
        }


class TaskCreateForm(TaskForm):
    class Meta(TaskForm.Meta):
        fields = ['title', 'project', 'assigned_to', 'start_date', 'due_date', 'day_report']


class StaffTaskUpdateForm(forms.ModelForm):
    class Meta:
        model = Task
        fields = ['status', 'day_report']
        widgets = {
            'status': forms.Select(attrs={'class': 'form-select'}),
            'day_report': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
        }


class ProjectForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ['name', 'client', 'start_date', 'end_date', 'priority', 'status']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'client': forms.TextInput(attrs={'class': 'form-control'}),
            'start_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'end_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'priority': forms.Select(attrs={'class': 'form-select'}),
            'status': forms.Select(attrs={'class': 'form-select'}),
        }

    def clean(self):
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')
        if start_date and end_date and end_date < start_date:
            self.add_error('end_date', 'End date cannot be earlier than start date.')
        return cleaned_data


class SystemSettingsForm(forms.ModelForm):
    reminder_time = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control',
                'placeholder': '09:00',
                'maxlength': '5',
                'inputmode': 'numeric',
                'autocomplete': 'off',
            }
        ),
    )
    reminder_period = forms.ChoiceField(
        choices=[('AM', 'AM'), ('PM', 'PM')],
        required=False,
        initial='AM',
        widget=forms.Select(attrs={'class': 'form-select'}),
    )

    class Meta:
        model = SystemSetting
        fields = ['company_name', 'working_days', 'reminder_time', 'support_email', 'support_phone']
        widgets = {
            'company_name': forms.TextInput(attrs={'class': 'form-control'}),
            'working_days': forms.TextInput(attrs={'class': 'form-control'}),
            'support_email': forms.EmailInput(attrs={'class': 'form-control'}),
            'support_phone': forms.TextInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.is_bound:
            field_name = self.add_prefix('reminder_time')
            raw_bound = (self.data.get(field_name) or '').strip()
            normalized_bound = self._normalize_time_text(raw_bound)
            if normalized_bound and normalized_bound != raw_bound:
                mutable_data = self.data.copy()
                mutable_data[field_name] = normalized_bound
                self.data = mutable_data
        if self.instance and self.instance.pk and self.instance.reminder_time:
            instance_time = self.instance.reminder_time
            if isinstance(instance_time, str):
                parsed = None
                for pattern in ('%H:%M:%S', '%H:%M'):
                    try:
                        parsed = datetime.strptime(instance_time, pattern).time()
                        break
                    except ValueError:
                        continue
                if parsed:
                    instance_time = parsed
            if hasattr(instance_time, 'strftime'):
                self.fields['reminder_time'].initial = instance_time.strftime('%I:%M')
                self.fields['reminder_period'].initial = instance_time.strftime('%p')

    def _normalize_time_text(self, token):
        token = (token or '').strip()
        if not token:
            return ''
        token = token.replace(';', ':').replace('.', ':')
        if re.fullmatch(r'\d{1,2}:\d{1,2}:\d{1,2}', token):
            token = ':'.join(token.split(':')[:2])
        if re.fullmatch(r'\d{5,}', token):
            token = token[:4]
        if re.fullmatch(r'\d{1,2}:\d{1,2}', token):
            hh_raw, mm_raw = token.split(':', 1)
            hh, mm = int(hh_raw), int(mm_raw)
            if 0 <= hh <= 23 and 0 <= mm <= 59:
                return f'{hh:02d}:{mm:02d}'
            return ''
        if re.fullmatch(r'\d{1,2}', token):
            hh = int(token)
            if 0 <= hh <= 23:
                return f'{hh:02d}:00'
            return ''
        if re.fullmatch(r'\d{3,4}', token):
            token = token.zfill(4)
            hh, mm = int(token[:2]), int(token[2:])
            if 0 <= hh <= 23 and 0 <= mm <= 59:
                return f'{hh:02d}:{mm:02d}'
        return ''

    def clean_reminder_time(self):
        raw = (self.cleaned_data.get('reminder_time') or '').strip()
        period = (self.cleaned_data.get('reminder_period') or 'AM').strip().upper()
        raw = self._normalize_time_text(raw) or raw

        def normalize(token):
            normalized = self._normalize_time_text(token)
            return normalized or None

        if 'AM' in raw.upper() or 'PM' in raw.upper():
            compact = ' '.join(raw.upper().split())
            token = compact.replace(' AM', '').replace(' PM', '')
            normalized = normalize(token)
            meridiem = 'AM' if ' AM' in compact else 'PM'
            if normalized:
                try:
                    return datetime.strptime(f'{normalized} {meridiem}', '%I:%M %p').time()
                except ValueError:
                    pass

        normalized = normalize(raw)
        if normalized and period in {'AM', 'PM'}:
            try:
                return datetime.strptime(f'{normalized} {period}', '%I:%M %p').time()
            except ValueError:
                pass

        if normalized:
            try:
                return datetime.strptime(normalized, '%H:%M').time()
            except ValueError:
                pass

        raise forms.ValidationError('Use valid time like 09:00 and choose AM/PM.')


class StaffProfileForm(forms.ModelForm):
    class Meta:
        model = Staff
        fields = ['name', 'email', 'contact_number', 'role', 'reporting_officer']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'contact_number': forms.TextInput(attrs={'class': 'form-control'}),
            'role': forms.TextInput(attrs={'class': 'form-control', 'readonly': 'readonly'}),
            'reporting_officer': forms.TextInput(attrs={'class': 'form-control', 'readonly': 'readonly'}),
        }

    def clean_email(self):
        email = (self.cleaned_data.get('email') or '').strip().lower()
        if not email:
            raise forms.ValidationError("Email is required.")
        qs = Staff.objects.filter(email__iexact=email)
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError("This email is already in use.")
        return email


class StaffNotificationSettingForm(forms.ModelForm):
    class Meta:
        model = StaffNotificationSetting
        fields = [
            'email_reminders',
            'in_app_reminders',
            'due_tomorrow_enabled',
            'overdue_enabled',
            'mention_enabled',
        ]
        widgets = {
            'email_reminders': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'in_app_reminders': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'due_tomorrow_enabled': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'overdue_enabled': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'mention_enabled': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }


class StaffAttendanceForm(forms.ModelForm):
    PERIOD_CHOICES = [
        ('AM', 'AM'),
        ('PM', 'PM'),
    ]

    check_in = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control',
                'placeholder': '09:30',
                'maxlength': '5',
                'inputmode': 'numeric',
                'autocomplete': 'off',
            }
        ),
    )
    check_in_period = forms.ChoiceField(
        choices=PERIOD_CHOICES,
        required=False,
        initial='AM',
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
    check_out = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control',
                'placeholder': '06:15',
                'maxlength': '5',
                'inputmode': 'numeric',
                'autocomplete': 'off',
            }
        ),
    )
    check_out_period = forms.ChoiceField(
        choices=PERIOD_CHOICES,
        required=False,
        initial='PM',
        widget=forms.Select(attrs={'class': 'form-select'}),
    )

    class Meta:
        model = StaffAttendance
        fields = ['attendance_date', 'check_in', 'check_out', 'status', 'note']
        widgets = {
            'attendance_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'status': forms.Select(attrs={'class': 'form-select'}),
            'note': forms.TextInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            if self.instance.check_in:
                self.fields['check_in'].initial = self.instance.check_in.strftime('%I:%M')
                self.fields['check_in_period'].initial = self.instance.check_in.strftime('%p')
            if self.instance.check_out:
                self.fields['check_out'].initial = self.instance.check_out.strftime('%I:%M')
                self.fields['check_out_period'].initial = self.instance.check_out.strftime('%p')

    def _parse_time(self, value, period_value, field_name):
        raw = (value or '').strip()
        if not raw:
            return None
        period = (period_value or '').strip().upper()
        raw = raw.replace(';', ':').replace('.', ':')

        def normalize_token(token):
            token = token.strip()
            if not token:
                return None
            if re.fullmatch(r'\d{5,}', token):
                token = token[:4]
            if re.fullmatch(r'\d{1,2}:\d{1,2}:\d{1,2}', token):
                token = ':'.join(token.split(':')[:2])
            if re.fullmatch(r'\d{1,2}:\d{1,2}', token):
                hour_raw, minute_raw = token.split(':', 1)
                hour = int(hour_raw)
                minute = int(minute_raw)
                if 0 <= hour <= 23 and 0 <= minute <= 59:
                    return f'{hour:02d}:{minute:02d}'
                return None
            if re.fullmatch(r'\d{1,2}', token):
                hour = int(token)
                if 0 <= hour <= 23:
                    return f'{hour:02d}:00'
                return None
            if re.fullmatch(r'\d{3,4}', token):
                token = token.zfill(4)
                hour = int(token[:2])
                minute = int(token[2:])
                if 0 <= hour <= 23 and 0 <= minute <= 59:
                    return f'{hour:02d}:{minute:02d}'
                return None
            return None

        # If user typed AM/PM in the input itself, trust that first.
        if 'AM' in raw.upper() or 'PM' in raw.upper():
            try:
                compact = ' '.join(raw.upper().split())
                token = compact.replace(' AM', '').replace(' PM', '')
                normalized = normalize_token(token)
                meridiem = 'AM' if ' AM' in compact else 'PM'
                if normalized:
                    return datetime.strptime(f'{normalized} {meridiem}', '%I:%M %p').time()
            except ValueError:
                pass
        # Otherwise always apply the selected AM/PM period.
        if period in {'AM', 'PM'}:
            try:
                normalized = normalize_token(raw)
                if normalized:
                    return datetime.strptime(f'{normalized} {period}', '%I:%M %p').time()
            except ValueError:
                pass
        # Fallback: allow 24-hour input.
        try:
            normalized = normalize_token(raw)
            if normalized:
                return datetime.strptime(normalized, '%H:%M').time()
        except ValueError:
            pass
        self.add_error(field_name, 'Use valid time like 09:30 and choose AM/PM.')
        return None

    def clean(self):
        cleaned_data = super().clean()
        check_in = self._parse_time(
            cleaned_data.get('check_in'),
            cleaned_data.get('check_in_period'),
            'check_in',
        )
        check_out = self._parse_time(
            cleaned_data.get('check_out'),
            cleaned_data.get('check_out_period'),
            'check_out',
        )
        cleaned_data['check_in'] = check_in
        cleaned_data['check_out'] = check_out
        if check_in and check_out and check_out <= check_in:
            self.add_error('check_out', 'Check-out time must be later than check-in time.')
        return cleaned_data


class StaffLeaveApplyForm(forms.ModelForm):
    class Meta:
        model = StaffLeaveRequest
        fields = ['start_date', 'end_date', 'reason']
        widgets = {
            'start_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'end_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'reason': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
        }

    def __init__(self, *args, **kwargs):
        self.staff = kwargs.pop('staff', None)
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')
        if start_date and end_date and end_date < start_date:
            self.add_error('end_date', 'End date cannot be earlier than start date.')
            return cleaned_data
        if self.staff and start_date and end_date:
            overlap_exists = StaffLeaveRequest.objects.filter(
                staff=self.staff,
                status__in=[StaffLeaveRequest.STATUS_PENDING, StaffLeaveRequest.STATUS_APPROVED],
                start_date__lte=end_date,
                end_date__gte=start_date,
            ).exists()
            if overlap_exists:
                self.add_error('start_date', 'You already have a pending/approved leave in this range.')
        return cleaned_data


class StaffTimesheetDailyForm(forms.ModelForm):
    class Meta:
        model = StaffTimesheetEntry
        fields = ['work_date', 'task', 'hours_spent', 'work_summary']
        widgets = {
            'work_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'task': forms.Select(attrs={'class': 'form-select'}),
            'hours_spent': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.25', 'min': '0.25'}),
            'work_summary': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }

    def __init__(self, *args, **kwargs):
        staff = kwargs.pop('staff', None)
        super().__init__(*args, **kwargs)
        self.fields['task'].required = False
        if staff:
            self.fields['task'].queryset = Task.objects.filter(assigned_to=staff).order_by('-due_date', 'title')


class StaffGoalForm(forms.ModelForm):
    class Meta:
        model = StaffGoal
        fields = ['title', 'target_value', 'current_value', 'start_date', 'end_date', 'status', 'note']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'target_value': forms.NumberInput(attrs={'class': 'form-control', 'min': '1'}),
            'current_value': forms.NumberInput(attrs={'class': 'form-control', 'min': '0'}),
            'start_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'end_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'status': forms.Select(attrs={'class': 'form-select'}),
            'note': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }

    def clean(self):
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')
        if start_date and end_date and end_date < start_date:
            self.add_error('end_date', 'End date cannot be earlier than start date.')
        return cleaned_data


class StaffDocumentUploadForm(forms.ModelForm):
    class Meta:
        model = StaffDocument
        fields = ['title', 'category', 'task', 'file']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'task': forms.Select(attrs={'class': 'form-select'}),
            'file': forms.ClearableFileInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        staff = kwargs.pop('staff', None)
        super().__init__(*args, **kwargs)
        self.fields['task'].required = False
        if staff:
            self.fields['task'].queryset = Task.objects.filter(assigned_to=staff).order_by('-due_date', 'title')


class HelpdeskTicketForm(forms.ModelForm):
    class Meta:
        model = HelpdeskTicket
        fields = ['subject', 'description', 'priority']
        widgets = {
            'subject': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
            'priority': forms.Select(attrs={'class': 'form-select'}),
        }


class TaskCommentForm(forms.ModelForm):
    parent_id = forms.IntegerField(required=False, widget=forms.HiddenInput())

    class Meta:
        model = TaskComment
        fields = ['text']
        widgets = {
            'text': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Add a comment. Use @username to mention.'}),
        }

    def clean_text(self):
        text = (self.cleaned_data.get('text') or '').strip()
        if not text:
            raise forms.ValidationError('Comment cannot be empty.')
        return text


class TaskAttachmentForm(forms.ModelForm):
    MAX_FILE_SIZE = 5 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'.pdf', '.doc', '.docx', '.txt', '.png', '.jpg', '.jpeg', '.xlsx', '.csv'}

    class Meta:
        model = TaskAttachment
        fields = ['title', 'file']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Attachment title (optional)'}),
            'file': forms.ClearableFileInput(attrs={'class': 'form-control'}),
        }

    def clean_file(self):
        upload = self.cleaned_data.get('file')
        if not upload:
            raise forms.ValidationError('Please choose a file.')
        if upload.size > self.MAX_FILE_SIZE:
            raise forms.ValidationError('File size must be 5MB or less.')
        name = upload.name.lower()
        extension = ''
        if '.' in name:
            extension = name[name.rfind('.'):]
        if extension not in self.ALLOWED_EXTENSIONS:
            raise forms.ValidationError('Unsupported file type.')
        return upload
