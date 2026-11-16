from django.contrib import admin
from .models import ManualPayment, Subject, CurriculumUnit, CurriculumLesson, FCMDeviceToken


@admin.register(FCMDeviceToken)
class FCMDeviceTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'platform', 'app_version', 'is_active', 'last_seen_at')
    list_filter = ('platform', 'is_active')
    search_fields = ('user__username', 'user__email', 'installation_id')
    readonly_fields = ('created_at', 'last_seen_at')

@admin.register(ManualPayment)
class ManualPaymentAdmin(admin.ModelAdmin):
    list_display = ('user', 'payment_type', 'amount', 'phone_number', 'status', 'created_at')
    list_filter = ('status', 'payment_type', 'created_at')
    search_fields = ('user__username', 'phone_number')
    readonly_fields = ('created_at',)
    list_editable = ('status',)

@admin.register(Subject)
class SubjectAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)

class CurriculumLessonInline(admin.TabularInline):
    model = CurriculumLesson
    extra = 1

@admin.register(CurriculumUnit)
class CurriculumUnitAdmin(admin.ModelAdmin):
    list_display = ('title', 'subject', 'grade', 'term', 'order')
    list_filter = ('grade', 'term', 'subject')
    search_fields = ('title',)
    inlines = [CurriculumLessonInline]

@admin.register(CurriculumLesson)
class CurriculumLessonAdmin(admin.ModelAdmin):
    list_display = ('title', 'unit', 'order')
    list_filter = ('unit__grade', 'unit__term', 'unit__subject')
    search_fields = ('title', 'unit__title')
