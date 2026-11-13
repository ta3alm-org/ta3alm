"""
core/forms.py
ملاحظة: فورمز تعديل المستخدمين من الإدارة انتقلت إلى dashboard_admin/forms.py
هذا الملف يبقى فارغاً للتوافق مع أي imports قديمة.
"""

# للتوافق مع أي كود قديم يستورد من هنا
from dashboard_admin.forms import (
    AdminUserEditForm      as OwnerUserEditForm,
    AdminTeacherEditForm   as OwnerTeacherEditForm,
    AdminStudentEditForm   as OwnerStudentEditForm,
    AdminAssistantEditForm as OwnerAssistantEditForm,
)

__all__ = [
    'OwnerUserEditForm',
    'OwnerTeacherEditForm',
    'OwnerStudentEditForm',
    'OwnerAssistantEditForm',
    'ManualPaymentForm',
]

from django import forms
from django.utils.translation import gettext_lazy as _
from .models import ManualPayment

class ManualPaymentForm(forms.ModelForm):
    class Meta:
        model = ManualPayment
        fields = ['phone_number', 'receipt_image']
        widgets = {
            'phone_number': forms.TextInput(attrs={'class': 'form-control', 'placeholder': _('رقم المحفظة أو الحساب الذي تم التحويل منه')}),
            'receipt_image': forms.FileInput(attrs={'class': 'form-control', 'accept': 'image/*'}),
        }