"""
dashboard_admin/forms.py
نماذج لوحة الإدارة
"""
from django import forms
from django.contrib.auth import get_user_model
from teachers.models import TeacherProfile
from accounts.models import StudentProfile
from assistants.models import AssistantProfile
from .models import AdminProfile, AdminRole

User = get_user_model()


# ----------------------------------------------------------
# تعديل بيانات مستخدم (من لوحة الإدارة)
# ----------------------------------------------------------
class AdminUserEditForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'phone', 'national_id', 'custom_id', 'role']
        labels = {
            'first_name':  'الاسم الأول',
            'last_name':   'الاسم الأخير',
            'email':       'البريد الإلكتروني',
            'phone':       'رقم الهاتف',
            'national_id': 'الرقم القومي',
            'custom_id':   'الكود التعريفي',
            'role':        'الدور',
        }
        widgets = {
            'first_name':  forms.TextInput(attrs={'class': 'form-control'}),
            'last_name':   forms.TextInput(attrs={'class': 'form-control'}),
            'email':       forms.EmailInput(attrs={'class': 'form-control'}),
            'phone':       forms.TextInput(attrs={'class': 'form-control'}),
            'national_id': forms.TextInput(attrs={'class': 'form-control'}),
            'custom_id':   forms.TextInput(attrs={'class': 'form-control'}),
            'role':        forms.Select(attrs={'class': 'form-select'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['role'].disabled = True
        self.fields['role'].help_text = 'لا يمكن تغيير الدور مباشرة للحفاظ على سلامة البيانات. إذا لزم الأمر، قم بحذف الحساب وإنشاء حساب جديد بالدور المطلوب.'

    def clean_role(self):
        # Prevent role change through this form to avoid profile conflicts
        return self.instance.role



class AdminTeacherEditForm(forms.ModelForm):
    subscription_end_date = forms.DateTimeField(
        label='تاريخ انتهاء الاشتراك',
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
    )

    class Meta:
        model = TeacherProfile
        fields = ['subject', 'bio', 'subscription_end_date', 'current_plan']
        labels = {
            'subject':      'المادة',
            'bio':          'نبذة',
            'current_plan': 'الباقة الحالية',
        }
        widgets = {
            'subject':      forms.Select(attrs={'class': 'form-select'}),
            'bio':          forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'current_plan': forms.Select(attrs={'class': 'form-select'}),
        }


class AdminStudentEditForm(forms.ModelForm):
    class Meta:
        model = StudentProfile
        fields = ['parent_phone']
        labels = {'parent_phone': 'رقم ولي الأمر'}
        widgets = {'parent_phone': forms.TextInput(attrs={'class': 'form-control'})}


class AdminAssistantEditForm(forms.ModelForm):
    class Meta:
        model = AssistantProfile
        fields = ['phone']
        labels = {'phone': 'رقم الهاتف'}
        widgets = {'phone': forms.TextInput(attrs={'class': 'form-control'})}


# ----------------------------------------------------------
# تعيين مسؤول جديد
# ----------------------------------------------------------
class AppointAdminForm(forms.ModelForm):
    user_email = forms.EmailField(
        label='البريد الإلكتروني للمستخدم',
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'أدخل إيميل المستخدم'}),
    )

    class Meta:
        model = AdminProfile
        fields = ['admin_role', 'notes']
        labels = {
            'admin_role': 'الدور الإداري',
            'notes':      'ملاحظات',
        }
        widgets = {
            'admin_role': forms.Select(attrs={'class': 'form-select'}),
            'notes':      forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
        }

# ----------------------------------------------------------
# نماذج المناهج الدراسية
# ----------------------------------------------------------
from core.models import CurriculumUnit, CurriculumLesson

class CurriculumUnitForm(forms.ModelForm):
    class Meta:
        model = CurriculumUnit
        fields = ['title', 'subject', 'grade', 'term', 'order']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'subject': forms.Select(attrs={'class': 'form-select'}),
            'grade': forms.Select(attrs={'class': 'form-select'}),
            'term': forms.Select(attrs={'class': 'form-select'}),
            'order': forms.NumberInput(attrs={'class': 'form-control'}),
        }

CurriculumLessonFormSet = forms.inlineformset_factory(
    CurriculumUnit, CurriculumLesson,
    fields=['title', 'order'],
    extra=1,
    can_delete=True,
    widgets={
        'title': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
        'order': forms.NumberInput(attrs={'class': 'form-control form-control-sm', 'style': 'width: 80px;'}),
    }
)


# ----------------------------------------------------------
# إنشاء مسؤول جديد بالكامل (من الصفر)
# ----------------------------------------------------------
class CreateAdminForm(forms.ModelForm):
    first_name = forms.CharField(
        label='الاسم الأول',
        widget=forms.TextInput(attrs={'class': 'form-control', 'required': True})
    )
    last_name = forms.CharField(
        label='الاسم الأخير',
        widget=forms.TextInput(attrs={'class': 'form-control', 'required': True})
    )
    email = forms.EmailField(
        label='البريد الإلكتروني',
        widget=forms.EmailInput(attrs={'class': 'form-control', 'required': True})
    )
    password = forms.CharField(
        label='كلمة المرور',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'required': True, 'minlength': '6'})
    )

    class Meta:
        model = AdminProfile
        fields = ['admin_role', 'notes']
        labels = {
            'admin_role': 'الدور الإداري',
            'notes':      'ملاحظات',
        }
        widgets = {
            'admin_role': forms.Select(attrs={'class': 'form-select'}),
            'notes':      forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
        }

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("يوجد مستخدم بالفعل بهذا البريد الإلكتروني. يرجى استخدام (تعيين مسؤول موجود).")
        return email
