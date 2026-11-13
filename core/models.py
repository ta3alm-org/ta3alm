from django.db import models
from django.utils.translation import gettext_lazy as _

class SiteSetting(models.Model):
    is_maintenance_mode = models.BooleanField(default=False, verbose_name=_("وضع الصيانة"))
    
    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def load(cls):
        obj, created = cls.objects.get_or_create(pk=1)
        return obj
    

# core/models.py
from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

class Notification(models.Model):
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications', verbose_name=_("المستقبل"))
    title = models.CharField(max_length=255, verbose_name=_("العنوان"))
    message = models.TextField(verbose_name=_("الرسالة"))
    link = models.CharField(max_length=255, blank=True, null=True, verbose_name=_("الرابط"))
    is_read = models.BooleanField(default=False, verbose_name=_("مقروءة"))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("وقت الإنشاء"))

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.recipient} - {self.title}"
    
# قائمة الصفوف (للاستخدام في الفلترة)
GRADE_CHOICES = (
    ('1_primary', _('أولى ابتدائي')), ('2_primary', _('ثانية ابتدائي')), ('3_primary', _('ثالثة ابتدائي')),
    ('4_primary', _('رابعة ابتدائي')), ('5_primary', _('خامسة ابتدائي')), ('6_primary', _('سادسة ابتدائي')),
    ('1_prep', _('أولى إعدادي')), ('2_prep', _('ثانية إعدادي')), ('3_prep', _('ثالثة إعدادي')),
    ('1_sec', _('أولى ثانوي')), ('2_sec', _('ثانية ثانوي')), ('3_sec', _('ثالثة ثانوي')),
)

class Subject(models.Model):
    name = models.CharField(max_length=50, verbose_name="اسم المادة")
    # الصفوف التي تدرس فيها هذه المادة (يمكن اختيار أكثر من صف)
    # سنستخدم حقل نصي بسيط أو JSON، لكن للأسهل سنستخدم MultiselectField (مكتبة خارجية)
    # أو ببساطة: نجعل المادة عامة، ونفلتر بالمعلم.
    # الحل الأبسط: لا نربط المادة بالصف في الداتا بيز، بل نربط المعلم بالمادة.
    
    class Meta:
        verbose_name = "المادة"
        verbose_name_plural = "المواد الدراسية"

    def __str__(self):
        return self.name

class ManualPayment(models.Model):
    STATUS_CHOICES = (
        ('pending', _('قيد المراجعة')),
        ('approved', _('مقبول')),
        ('rejected', _('مرفوض')),
    )
    TYPE_CHOICES = (
        ('teacher_subscription', _('اشتراك معلم')),
        ('student_package', _('شراء حزمة طالب')),
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, verbose_name="المستخدم")
    amount = models.PositiveIntegerField(verbose_name="المبلغ")
    payment_type = models.CharField(max_length=50, choices=TYPE_CHOICES, verbose_name="نوع العملية")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', verbose_name="الحالة")
    
    target_id = models.PositiveIntegerField(help_text="ID الباقة أو الحزمة", null=True, blank=True)
    
    phone_number = models.CharField(max_length=50, verbose_name="رقم المحفظة / انستا باي")
    receipt_image = models.ImageField(upload_to='receipts/', verbose_name="صورة الإيصال (سكرين شوت)")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="تاريخ الطلب")

    def __str__(self):
        return f"{self.user} - {self.get_payment_type_display()} - {self.get_status_display()}"

    def save(self, *args, **kwargs):
        # تنفيذ عند القبول فقط (التحويل من حالة غير مقبول إلى مقبول)
        if self.pk:
            old_payment = ManualPayment.objects.get(pk=self.pk)
            if old_payment.status != 'approved' and self.status == 'approved':
                # منطق التفعيل
                if self.payment_type == 'teacher_subscription':
                    self.activate_teacher_subscription()
                elif self.payment_type == 'student_package':
                    self.activate_student_package()
        super().save(*args, **kwargs)

    def activate_teacher_subscription(self):
        from teachers.models import SubscriptionPlan, TeacherProfile
        from django.utils import timezone
        from datetime import timedelta
        try:
            teacher = self.user.teacher_profile
            plan = SubscriptionPlan.objects.get(id=self.target_id)
            teacher.current_plan = plan
            # إذا كان الاشتراك ساري نضيف 30 يوماً على المتبقي، وإلا من اليوم
            if teacher.subscription_end_date and teacher.subscription_end_date > timezone.now():
                teacher.subscription_end_date += timedelta(days=30)
            else:
                teacher.subscription_end_date = timezone.now() + timedelta(days=30)
            teacher.save()
        except Exception as e:
            print(f"Error activating teacher subscription: {e}")

    def activate_student_package(self):
        from students.models import PackageEnrollment
        from teachers.models import CoursePackage
        try:
            student = self.user.student_profile
            package = CoursePackage.objects.get(id=self.target_id)
            enrollment, created = PackageEnrollment.objects.get_or_create(student=student, package=package)
            enrollment.is_paid = True
            enrollment.save()
        except Exception as e:
            print(f"Error activating student package: {e}")

TERM_CHOICES = (
    ('1', _('الترم الأول')),
    ('2', _('الترم الثاني')),
)

class CurriculumUnit(models.Model):
    title = models.CharField(max_length=200, verbose_name="اسم الوحدة / المحور")
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE, related_name='units', verbose_name="المادة")
    grade = models.CharField(max_length=20, choices=GRADE_CHOICES, verbose_name="الصف الدراسي")
    term = models.CharField(max_length=1, choices=TERM_CHOICES, verbose_name="الترم")
    order = models.PositiveIntegerField(default=1, verbose_name="الترتيب")

    class Meta:
        ordering = ['grade', 'subject', 'term', 'order']
        verbose_name = "وحدة دراسية"
        verbose_name_plural = "الوحدات الدراسية"

    def __str__(self):
        return f"[{self.get_grade_display()} - {self.get_term_display()}] {self.subject.name} - {self.title}"


class CurriculumLesson(models.Model):
    unit = models.ForeignKey(CurriculumUnit, on_delete=models.CASCADE, related_name='lessons', verbose_name="الوحدة")
    title = models.CharField(max_length=200, verbose_name="اسم الدرس")
    order = models.PositiveIntegerField(default=1, verbose_name="الترتيب")

    class Meta:
        ordering = ['unit', 'order']
        verbose_name = "درس"
        verbose_name_plural = "الدروس"

    def __str__(self):
        return f"{self.unit.title} - {self.title}"