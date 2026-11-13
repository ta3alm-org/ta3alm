from django.db import models, transaction
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta
import re
import random
import string
from core.models import Subject
from core.constants import GRADE_CHOICES  # ┘à╪╡╪»╪▒ ┘à┘ê╪¡┘æ╪» ΓÇö ┘ä╪º ╪¬┘Å┘â╪▒╪▒ ╪º┘ä╪¬╪╣╪▒┘è┘ü ┘ç┘å╪º

# ==========================================
# 2. ╪«╪╖╪╖ ╪º┘ä╪ú╪│╪╣╪º╪▒ (Subscription Plans)
# ==========================================
class SubscriptionPlan(models.Model):
    name = models.CharField(max_length=100, verbose_name=_("╪º╪│┘à ╪º┘ä╪¿╪º┘é╪⌐"))
    price = models.PositiveIntegerField(verbose_name=_("╪º┘ä╪│╪╣╪▒ (EGP)"))
    description = models.TextField(blank=True, verbose_name=_("┘ê╪╡┘ü ╪º┘ä╪¿╪º┘é╪⌐"))

    # --- ┘é┘è┘ê╪» ╪º┘ä╪¿╪º┘é╪⌐ ---
    student_limit = models.PositiveIntegerField(default=1000, verbose_name=_("╪¡╪» ╪º┘ä╪╖┘ä╪º╪¿"))
    group_limit = models.PositiveIntegerField(default=5, verbose_name=_("╪¡╪» ╪º┘ä┘à╪¼┘à┘ê╪╣╪º╪¬"))
    assistant_limit = models.PositiveIntegerField(default=2, verbose_name=_("╪¡╪» ╪º┘ä┘à╪│╪º╪╣╪»┘è┘å"))

    # --- ╪╡┘ä╪º╪¡┘è╪º╪¬ (┘å╪╣┘à/┘ä╪º) ---
    allow_online_packages = models.BooleanField(default=False, verbose_name=_("┘à╪│┘à┘ê╪¡ ╪¿╪º┘ä╪¡╪▓┘à ╪º┘ä╪ú┘ê┘å┘ä╪º┘è┘å"))
    allow_question_images = models.BooleanField(default=False, verbose_name=_("┘à╪│┘à┘ê╪¡ ╪¿╪╡┘ê╪▒ ╪º┘ä╪ú╪│╪ª┘ä╪⌐"))
    is_default = models.BooleanField(default=False, verbose_name=_("╪¿╪º┘é╪⌐ ╪º┘ü╪¬╪▒╪º╪╢┘è╪⌐ (┘à╪¼╪º┘å┘è╪⌐)"))

    def save(self, *args, **kwargs):
        # ╪º╪│╪¬╪«╪»╪º┘à transaction ┘ä╪¬╪¼┘å╪¿ Race Condition
        if self.is_default:
            with transaction.atomic():
                SubscriptionPlan.objects.filter(is_default=True).exclude(pk=self.pk).update(is_default=False)
                super().save(*args, **kwargs)
        else:
            super().save(*args, **kwargs)
    def __str__(self):
        return f"{self.name} ({self.price} EGP)"

# ==========================================
# 3. ╪¿╪▒┘ê┘ü╪º┘è┘ä ╪º┘ä┘à╪╣┘ä┘à
# ==========================================
class TeacherProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='teacher_profile')
    
    bio = models.TextField(blank=True, verbose_name=_('┘å╪¿╪░╪⌐ ╪╣┘å ╪º┘ä┘à╪╣┘ä┘à'))
    subject = models.ForeignKey(Subject, on_delete=models.SET_NULL, null=True, verbose_name="╪º┘ä┘à╪º╪»╪⌐")
    image = models.ImageField(upload_to='teachers/', blank=True, null=True, verbose_name=_('╪╡┘ê╪▒╪⌐ ╪º┘ä┘à╪╣┘ä┘à'))
    
    # ╪º┘ä╪º╪┤╪¬╪▒╪º┘â
    subscription_end_date = models.DateTimeField(null=True, blank=True, verbose_name=_('╪¬╪º╪▒┘è╪« ╪º┘å╪¬┘ç╪º╪í ╪º┘ä╪º╪┤╪¬╪▒╪º┘â'))
    is_trial_used = models.BooleanField(default=False, verbose_name=_('┘ç┘ä ╪º╪│╪¬┘ç┘ä┘â ╪º┘ä╪┤┘ç╪▒ ╪º┘ä┘à╪¼╪º┘å┘è╪ƒ'))
    current_plan = models.ForeignKey(SubscriptionPlan, on_delete=models.SET_NULL, null=True, blank=True, verbose_name=_("╪º┘ä╪¿╪º┘é╪⌐ ╪º┘ä╪¡╪º┘ä┘è╪⌐"))

    def has_active_subscription(self):
        if not self.subscription_end_date: return False
        return self.subscription_end_date > timezone.now()

    def days_remaining(self):
        if not self.subscription_end_date: return 0
        return max((self.subscription_end_date - timezone.now()).days, 0)
    
    def get_student_limit(self):
        return self.current_plan.student_limit if self.current_plan else 0

    def get_total_students(self):
        from django.apps import apps
        Enrollment = apps.get_model('students', 'Enrollment')
        return Enrollment.objects.filter(group__teacher=self, is_active=True).count()
        # ╪»╪º┘ä╪⌐ ╪¬╪▒╪¼╪╣ ┘é╪º╪ª┘à╪⌐ IDs ╪º┘ä┘à╪¼┘à┘ê╪╣╪º╪¬ ╪º┘ä┘à╪│┘à┘ê╪¡╪⌐ (╪º┘ä╪ú┘é╪»┘à ┘ü╪º┘ä╪ú╪¡╪»╪½ ╪¡╪│╪¿ ╪º┘ä╪¡╪»)
    def get_allowed_group_ids(self):
        limit = self.current_plan.group_limit if self.current_plan else 0
        # ┘å╪ú╪«╪░ ╪ú┘é╪»┘à N ┘à╪¼┘à┘ê╪╣╪º╪¬ ┘ü┘é╪╖
        return self.groups.order_by('created_at').values_list('id', flat=True)[:limit]

    # ┘ç┘ä ╪º┘ä╪¡╪▓┘à ┘à╪│┘à┘ê╪¡╪⌐ ┘ü┘è ╪º┘ä╪¿╪º┘é╪⌐ ╪º┘ä╪¡╪º┘ä┘è╪⌐╪ƒ
    def are_packages_allowed(self):
        return self.current_plan.allow_online_packages if self.current_plan else False

    @classmethod
    def ordered_for_home(cls):
        """ترتيب المعلمين للعرض في الرئيسية: أصحاب الصور الشخصية أولاً ثم الأعلى أقدمية."""
        from django.db.models import Case, When, Value, IntegerField, Q
        return (
            cls.objects
            .select_related('user', 'subject', 'current_plan')
            .filter(user__is_banned=False)
            .annotate(
                has_photo=Case(
                    When(~Q(image='') & Q(image__isnull=False), then=Value(0)),
                    default=Value(1),
                    output_field=IntegerField(),
                )
            )
            .order_by('has_photo', 'user__date_joined', 'id')
        )

    def __str__(self):
        return self.user.username

# ==========================================
# 4. ╪º┘ä┘à╪¼┘à┘ê╪╣╪⌐ (Group)
# ==========================================
class Group(models.Model):
    teacher = models.ForeignKey(TeacherProfile, on_delete=models.CASCADE, related_name='groups')
    name = models.CharField(max_length=100, verbose_name=_('╪º╪│┘à ╪º┘ä┘à╪¼┘à┘ê╪╣╪⌐'))
    grade = models.CharField(max_length=20, choices=GRADE_CHOICES, verbose_name=_('╪º┘ä╪╡┘ü ╪º┘ä╪»╪▒╪º╪│┘è'))
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.get_grade_display()}"

# ==========================================
# 5. ╪º┘ä┘à╪¡╪º╪╢╪▒╪⌐ (Lecture)
# ==========================================
class Lecture(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='lectures', null=True, blank=True)
    title = models.CharField(max_length=200, verbose_name=_('╪º┘ä╪╣┘å┘ê╪º┘å'))
    video_link = models.URLField(verbose_name=_('╪▒╪º╪¿╪╖ ╪º┘ä┘ü┘è╪»┘è┘ê'))
    description = models.TextField(blank=True, verbose_name=_('╪º┘ä┘ê╪╡┘ü'))
    is_active = models.BooleanField(default=True, verbose_name=_("┘à┘ü╪╣┘ä╪⌐"))
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self): return self.title

    def get_video_id(self):
        if not self.video_link: return None
        clean = self.video_link.strip()
        # ╪»╪╣┘à ┘è┘ê╪¬┘è┘ê╪¿ ┘ü┘é╪╖ ╪¡╪º┘ä┘è╪º┘ï ┘ü┘è ┘ç╪░╪º ╪º┘ä┘ü╪º┘å┘â╪┤┘å
        if 'youtube' not in clean and 'youtu.be' not in clean: return None
        patterns = [r'(?:v=|\/)([0-9A-Za-z_-]{11}).*', r'(?:youtu\.be\/)([0-9A-Za-z_-]{11})', r'(?:embed\/)([0-9A-Za-z_-]{11})']
        for p in patterns:
            match = re.search(p, clean)
            if match: return match.group(1)
        return None

# ==========================================
# 6. ╪ú┘â┘ê╪º╪» ╪º┘ä┘ü┘è╪»┘è┘ê
# ==========================================
class VideoCode(models.Model):
    lecture = models.ForeignKey(Lecture, on_delete=models.CASCADE, related_name='codes')
    code = models.CharField(max_length=10, unique=True, verbose_name=_('╪º┘ä┘â┘ê╪»'))
    
    max_views = models.PositiveIntegerField(default=1, verbose_name=_("╪¡╪» ╪º┘ä┘à╪┤╪º┘ç╪»╪º╪¬"))
    current_views = models.PositiveIntegerField(default=0, verbose_name=_("╪º┘ä┘à╪┤╪º┘ç╪»╪º╪¬ ╪º┘ä╪¡╪º┘ä┘è╪⌐"))
    
    is_used = models.BooleanField(default=False, verbose_name=_('╪¬┘à ╪º┘ä╪¬┘ü╪╣┘è┘ä'))
    used_by = models.ForeignKey('accounts.StudentProfile', on_delete=models.SET_NULL, null=True, blank=True)
    used_at = models.DateTimeField(null=True, blank=True)

    def is_expired(self):
        return self.current_views >= self.max_views

    @staticmethod
    def generate_random_code():
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))


class PDFFile(models.Model):
    # ┘è┘à┘â┘å ╪ú┘å ┘è┘â┘ê┘å ╪¬╪º╪¿╪╣╪º┘ï ┘ä┘à╪¼┘à┘ê╪╣╪⌐ (╪º╪«╪¬┘è╪º╪▒┘è)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='pdfs', null=True, blank=True)
    
    title = models.CharField(max_length=200, verbose_name=_('╪╣┘å┘ê╪º┘å ╪º┘ä┘à┘ä┘ü'))
    link = models.URLField(verbose_name=_('╪▒╪º╪¿╪╖ ╪º┘ä┘à┘ä┘ü (Drive/Direct)'))
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self): return self.title

    
# ==========================================
# 7. ╪º┘ä╪¡╪▓┘à ╪º┘ä╪¬╪╣┘ä┘è┘à┘è╪⌐ (Online Course Packages)
# ==========================================
class CoursePackage(models.Model):
    teacher = models.ForeignKey(TeacherProfile, on_delete=models.CASCADE, related_name='packages')
    title = models.CharField(max_length=200, verbose_name=_("╪º╪│┘à ╪º┘ä╪¡╪▓┘à╪⌐"))
    
    # ╪¡┘é┘ä ╪º┘ä╪╡┘ü (╪º┘ä╪¼╪»┘è╪») - ╪¿╪»┘ê┘å default ┘ä┘è╪¼╪¿╪▒┘â ╪╣┘ä┘ë ╪º╪«╪¬┘è╪º╪▒┘ç
    grade = models.CharField(max_length=20, choices=GRADE_CHOICES, verbose_name=_("╪º┘ä╪╡┘ü ╪º┘ä╪»╪▒╪º╪│┘è"))
    pdfs = models.ManyToManyField(PDFFile, related_name='packages', verbose_name=_("╪º┘ä┘à┘ä┘ü╪º╪¬ ╪º┘ä┘à╪«╪¬╪º╪▒╪⌐"), blank=True)    
    description = models.TextField(verbose_name=_("┘ê╪╡┘ü ╪º┘ä╪¡╪▓┘à╪⌐"))
    price = models.PositiveIntegerField(verbose_name=_("╪│╪╣╪▒ ╪º┘ä╪¡╪▓┘à╪⌐ (EGP)"))
    image = models.ImageField(upload_to='packages/', blank=True, null=True, verbose_name=_("╪╡┘ê╪▒╪⌐ ╪º┘ä╪║┘ä╪º┘ü"))
    
    # ╪º┘ä╪╣┘ä╪º┘é╪º╪¬ (ManyToMany) - ┘ç┘å╪º ┘å╪│╪¬╪«╪»┘à string ┘ä╪¬╪¼┘å╪¿ Circular Import ┘à╪╣ exams
    lectures = models.ManyToManyField(Lecture, related_name='packages', verbose_name=_("╪º┘ä┘à╪¡╪º╪╢╪▒╪º╪¬ ╪º┘ä┘à╪«╪¬╪º╪▒╪⌐"))
    exams = models.ManyToManyField('exams.Exam', related_name='packages', verbose_name=_("╪º┘ä╪º┘à╪¬╪¡╪º┘å╪º╪¬ ╪º┘ä┘à╪«╪¬╪º╪▒╪⌐"))
    
    view_limit = models.PositiveIntegerField(default=3, verbose_name=_("╪¡╪» ╪º┘ä┘à╪┤╪º┘ç╪»╪⌐ ┘ä┘ä┘ü┘è╪»┘è┘ê"))
    is_active = models.BooleanField(default=True, verbose_name=_("┘à╪¬╪º╪¡╪⌐ ┘ä┘ä╪┤╪▒╪º╪í"))
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self): return self.title

# ==========================================
# 8. ╪│╪¼┘ä ╪º┘ä┘à╪»┘ü┘ê╪╣╪º╪¬ (┘ä┘ä┘à╪╣┘ä┘à)
# ==========================================
class PaymentTransaction(models.Model):
    teacher = models.ForeignKey(TeacherProfile, on_delete=models.CASCADE)
    amount = models.PositiveIntegerField(verbose_name=_("╪º┘ä┘à╪¿┘ä╪║"))
    date = models.DateTimeField(auto_now_add=True, verbose_name=_("╪º┘ä╪¬╪º╪▒┘è╪«"))
    transaction_id = models.CharField(max_length=100, blank=True, null=True)


# ┘à╪¡┘ü╪╕╪⌐ ╪º┘ä┘à╪╣┘ä┘à
class Wallet(models.Model):
    teacher = models.OneToOneField(TeacherProfile, on_delete=models.CASCADE, related_name='wallet')
    balance = models.DecimalField(default=0.0, max_digits=10, decimal_places=2, verbose_name="╪º┘ä╪▒╪╡┘è╪» ╪º┘ä╪¡╪º┘ä┘è")
    total_earnings = models.DecimalField(default=0.0, max_digits=12, decimal_places=2, verbose_name="╪Ñ╪¼┘à╪º┘ä┘è ╪º┘ä╪ú╪▒╪¿╪º╪¡")
    
    def __str__(self):
        return f"┘à╪¡┘ü╪╕╪⌐: {self.teacher.user.username} ({self.balance} EGP)"

# ╪╖┘ä╪¿╪º╪¬ ╪º┘ä╪│╪¡╪¿
class WithdrawRequest(models.Model):
    METHODS = (
        ('vodafone', 'Vodafone Cash'),
        ('instapay', 'InstaPay'),
        ('bank', 'Bank Transfer'),
    )
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='withdrawals')
    amount = models.DecimalField(max_digits=10, decimal_places=2, verbose_name="╪º┘ä┘à╪¿┘ä╪║ ╪º┘ä┘à╪╖┘ä┘ê╪¿")
    method = models.CharField(max_length=20, choices=METHODS, verbose_name="╪╖╪▒┘è┘é╪⌐ ╪º┘ä╪│╪¡╪¿")
    details = models.TextField(verbose_name="╪¿┘è╪º┘å╪º╪¬ ╪º┘ä╪¬╪¡┘ê┘è┘ä (╪▒┘é┘à/╪¡╪│╪º╪¿)")
    is_paid = models.BooleanField(default=False, verbose_name="╪¬┘à ╪º┘ä╪¬╪¡┘ê┘è┘ä")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.amount} - {self.get_method_display()}"
