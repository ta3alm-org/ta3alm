from django import forms
from django.utils.translation import gettext_lazy as _
from .models import PerformanceLog

class PerformanceForm(forms.ModelForm):
    class Meta:
        model = PerformanceLog
        fields = [
            'is_present',
            'session_number', 
            'homework_score', 'homework_max',
            'class_exam_score', 'class_exam_max',
            'recitation_score', 'recitation_max',
            'comprehensive_exam_score', 'comprehensive_exam_max',
            'note'
        ]
        widgets = {
            'is_present': forms.CheckboxInput(attrs={'class': 'form-check-input', 'checked': True}),
            'note': forms.TextInput(attrs={'class': 'form-control', 'placeholder': _('ملاحظات...')}),
            
            # تنسيق حقول الدرجات (تحديد placeholder)
            'homework_score': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': _('الدرجة')}),
            'homework_max': forms.NumberInput(attrs={'class': 'form-control', 'value': 10}),
            
            'class_exam_score': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': _('الدرجة')}),
            'class_exam_max': forms.NumberInput(attrs={'class': 'form-control', 'value': 10}),
            
            'recitation_score': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': _('الدرجة')}),
            'recitation_max': forms.NumberInput(attrs={'class': 'form-control', 'value': 10}),

            'comprehensive_exam_score': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': _('الدرجة')}),
            'comprehensive_exam_max': forms.NumberInput(attrs={'class': 'form-control', 'value': 50}),
            'session_number': forms.NumberInput(attrs={'class': 'form-control', 'min': 1}),
        }