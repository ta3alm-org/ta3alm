from django.db import models, transaction
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta
import re
import random
import string
import urllib.parse
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
    allow_question_images = models.BooleanField(default=True, verbose_name=_("┘à╪│┘à┘ê╪¡ ╪¿╪╡┘ê╪▒ ╪º┘ä╪ú╪│╪ª┘ä╪⌐"))
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
    is_approved = models.BooleanField(default=False, db_index=True, verbose_name=_('معتمد من الإدارة'))
    approved_at = models.DateTimeField(null=True, blank=True, verbose_name=_('تاريخ الاعتماد'))

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
    def ordered_for_home(cls, approved_only: bool = True):
        """ترتيب المعلمين للعرض في الرئيسية: المعتمدون فقط وأصحاب الصور الشخصية أولاً ثم الأعلى أقدمية."""
        from django.db.models import Case, When, Value, IntegerField, Q
        qs = cls.objects.select_related('user', 'subject', 'current_plan').filter(user__is_banned=False)
        if approved_only:
            qs = qs.filter(is_approved=True)
        return (
            qs
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
    is_chat_locked = models.BooleanField(default=False, verbose_name='قفل شات المجموعة')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.get_grade_display()}"

# ==========================================
# 5. ╪º┘ä┘à╪¡╪º╪╢╪▒╪⌐ (Lecture)
# ==========================================
class Lecture(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='lectures', null=True, blank=True)
    title = models.CharField(max_length=200, verbose_name=_('╪º┘ä╪╣┘å┘ê╪º┘å'))
    video_link = models.URLField(max_length=2000, verbose_name=_('╪▒╪º╪¿╪╖ ╪º┘ä┘ü┘è╪»┘è┘ê'))
    description = models.TextField(blank=True, verbose_name=_('╪º┘ä┘ê╪╡┘ü'))
    is_active = models.BooleanField(default=True, verbose_name=_("┘à┘ü╪╣┘ä╪⌐"))
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self): return self.title

    @staticmethod
    def normalize_video_link(raw_link: str) -> str:
        """تنظيف رابط الفيديو واستخراج الرابط من iframe واختصار روابط يوتيوب الطويلة."""
        text = str(raw_link or '').strip()
        if not text:
            return ''
        if '<iframe' in text.lower():
            src_match = re.search(r'src\s*=\s*["\']([^"\']+)["\']', text, flags=re.IGNORECASE)
            if src_match:
                text = src_match.group(1).strip()
        lowered = text.lower()
        if 'youtube.com' in lowered or 'youtu.be' in lowered or 'youtube-nocookie.com' in lowered:
            match = re.search(
                r'(?:[?&]v=|youtu\.be/|youtube(?:-nocookie)?\.com/(?:embed|shorts|live|v)/)([0-9A-Za-z_-]{11})',
                text,
            )
            if match:
                return f'https://www.youtube.com/watch?v={match.group(1)}'
        return text

    def get_video_id(self):
        """استخراج معرّف يوتيوب (11 حرفاً) بعد تنظيف الرابط إن وجد."""
        clean = self.normalize_video_link(self.video_link)
        if not clean:
            return None
        if re.fullmatch(r'[0-9A-Za-z_-]{11}', clean):
            return clean
        lowered = clean.lower()
        if 'youtube' not in lowered and 'youtu.be' not in lowered:
            return None
        patterns = [
            r'(?:[?&]v=|youtu\.be/|youtube(?:-nocookie)?\.com/(?:embed|shorts|live|v)/)([0-9A-Za-z_-]{11})',
        ]
        for p in patterns:
            match = re.search(p, clean)
            if match:
                return match.group(1)
        return None

    @classmethod
    def classify_video_source(cls, raw_link: str) -> dict:
        """
        تصنيف وتطبيع أي رابط فيديو (YouTube، ملفات MP4/HLS/WebM مباشرة، Google Drive، Vimeo،
        Bunny Stream، Cloudflare Stream، Dailymotion، Loom، Streamable، Wistia، إلخ).
        """
        text = str(raw_link or '').strip()
        if not text:
            return {'kind': 'empty', 'url': ''}
        if '<iframe' in text.lower():
            src_match = re.search(r'src\s*=\s*["\']([^"\']+)["\']', text, flags=re.IGNORECASE)
            if src_match:
                text = src_match.group(1).strip()

        if re.fullmatch(r'[0-9A-Za-z_-]{11}', text):
            return {
                'kind': 'youtube',
                'youtube_id': text,
                'url': f'https://www.youtube.com/watch?v={text}',
            }

        lowered = text.lower()
        if 'youtube.com' in lowered or 'youtu.be' in lowered or 'youtube-nocookie.com' in lowered:
            yt_match = re.search(
                r'(?:[?&]v=|youtu\.be/|youtube(?:-nocookie)?\.com/(?:embed|shorts|live|v)/)([0-9A-Za-z_-]{11})',
                text,
            )
            if yt_match:
                yt_id = yt_match.group(1)
                return {
                    'kind': 'youtube',
                    'youtube_id': yt_id,
                    'url': f'https://www.youtube.com/watch?v={yt_id}',
                }

        if not (lowered.startswith('http://') or lowered.startswith('https://')):
            return {'kind': 'empty', 'url': ''}

        parsed = urllib.parse.urlparse(text)
        host = parsed.netloc.lower()
        path = parsed.path or ''
        path_l = path.lower()

        # تطبيع روابط Cloudflare Stream Watch إلى HLS Manifest
        cf_match = re.match(r'^/([0-9a-f]{32})(?:/watch)?/?$', path_l)
        if cf_match and ('cloudflarestream.com' in host or 'videodelivery.net' in host):
            uid = cf_match.group(1)
            sub_host = host if host.startswith('customer-') else 'videodelivery.net'
            return {
                'kind': 'direct_stream',
                'stream_format': 'hls',
                'url': f'https://{sub_host}/{uid}/manifest/video.m3u8',
            }

        # تطبيع روابط Dropbox للملفات المباشرة
        normalized_url = text
        if 'dropbox.com' in host:
            q = urllib.parse.parse_qs(parsed.query)
            q.pop('dl', None)
            q['raw'] = ['1']
            new_query = urllib.parse.urlencode(q, doseq=True)
            normalized_url = urllib.parse.urlunparse(
                ('https', 'dl.dropboxusercontent.com', parsed.path, parsed.params, new_query, '')
            )
        elif host == 'github.com':
            segs = [s for s in path.split('/') if s]
            if len(segs) >= 5 and segs[2] == 'blob':
                rest = '/'.join(segs[3:])
                normalized_url = f'https://raw.githubusercontent.com/{segs[0]}/{segs[1]}/{rest}'

        direct_exts = ('.mp4', '.m3u8', '.webm', '.mov', '.m4v', '.mkv', '.mpd', '.ogg', '.ogv', '.ts')
        if (
            any(path_l.endswith(ext) for ext in direct_exts)
            or '/video/upload/' in path_l
            or '/playlist.m3u8' in path_l
            or '/manifest/video.m3u8' in path_l
        ):
            stream_fmt = 'hls' if ('.m3u8' in path_l or '.mpd' in path_l) else 'mp4'
            return {
                'kind': 'direct_stream',
                'stream_format': stream_fmt,
                'url': normalized_url,
            }

        # Google Drive
        if 'drive.google.com' in host:
            m_drive = re.search(r'/file/d/([0-9A-Za-z_-]+)', path)
            file_id = m_drive.group(1) if m_drive else (urllib.parse.parse_qs(parsed.query).get('id') or [''])[0]
            if file_id:
                return {'kind': 'embed', 'url': f'https://drive.google.com/file/d/{file_id}/preview'}

        # Vimeo
        if 'vimeo.com' in host:
            if 'player.vimeo.com' in host:
                sep = '&' if '?' in text else '?'
                embed = text if 'playsinline=' in lowered else f'{text}{sep}playsinline=1&byline=0&portrait=0&title=0'
                return {'kind': 'embed', 'url': embed}
            m_vim = re.search(r'vimeo\.com/(?:video/|channels/[^/]+/|groups/[^/]+/videos/)?(\d+)(?:/([0-9A-Za-z]+))?', text)
            if m_vim:
                vid = m_vim.group(1)
                h_tok = m_vim.group(2)
                extra = f'&h={h_tok}' if h_tok else ''
                return {
                    'kind': 'embed',
                    'url': f'https://player.vimeo.com/video/{vid}?playsinline=1&byline=0&portrait=0&title=0{extra}',
                }

        # Bunny Stream (mediadelivery.net)
        if 'mediadelivery.net' in host:
            m_bunny = re.search(r'/(?:play|embed)/([^/]+)/([^/?#]+)', path)
            if m_bunny:
                lib_id, vid_id = m_bunny.group(1), m_bunny.group(2)
                return {
                    'kind': 'embed',
                    'url': f'https://iframe.mediadelivery.net/embed/{lib_id}/{vid_id}?autoplay=false&preload=true&responsive=true',
                }

        # Dailymotion
        if 'dailymotion.com' in host or host == 'dai.ly':
            m_dm = re.search(r'(?:dailymotion\.com/(?:embed/)?video/|dai\.ly/)([0-9A-Za-z]+)', text)
            if m_dm:
                return {
                    'kind': 'embed',
                    'url': f'https://www.dailymotion.com/embed/video/{m_dm.group(1)}?playsinline=1&ui-logo=0&sharing-enable=0',
                }

        # Loom
        if 'loom.com' in host:
            m_loom = re.search(r'loom\.com/(?:share|embed)/([0-9A-Za-z]+)', path)
            if m_loom:
                return {
                    'kind': 'embed',
                    'url': f'https://www.loom.com/embed/{m_loom.group(1)}?hide_owner=true&hide_share=true&hide_title=true',
                }

        # Streamable
        if 'streamable.com' in host:
            m_st = re.search(r'streamable\.com/(?:e/)?([0-9A-Za-z]+)', path)
            if m_st:
                return {'kind': 'embed', 'url': f'https://streamable.com/e/{m_st.group(1)}'}

        # Wistia
        if 'wistia.com' in host or 'wistia.net' in host:
            m_w = re.search(r'/(?:medias|iframe)/([0-9A-Za-z]+)', path)
            if m_w:
                return {'kind': 'embed', 'url': f'https://fast.wistia.net/embed/iframe/{m_w.group(1)}?videoFoam=true'}

        # Archive.org
        if 'archive.org' in host:
            m_ar = re.search(r'archive\.org/(?:details|embed)/([^/?#]+)', path)
            if m_ar:
                return {'kind': 'embed', 'url': f'https://archive.org/embed/{m_ar.group(1)}'}

        # Facebook Video
        if 'facebook.com' in host or 'fb.watch' in host:
            quoted = urllib.parse.quote(text, safe='')
            return {'kind': 'embed', 'url': f'https://www.facebook.com/plugins/video.php?href={quoted}&show_text=false'}

        return {'kind': 'embed', 'url': normalized_url}

    def is_direct_media_link(self) -> bool:
        return self.classify_video_source(self.video_link).get('kind') == 'direct_stream'

    def get_web_embed_url(self) -> str:
        info = self.classify_video_source(self.video_link)
        return info.get('url') or (self.video_link or '').strip()

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
    link = models.URLField(max_length=2000, verbose_name=_('╪▒╪º╪¿╪╖ ╪º┘ä┘à┘ä┘ü (Drive/Direct)'))
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
    STATUS_PENDING = 'pending'
    STATUS_PAID = 'paid'
    STATUS_REJECTED = 'rejected'
    STATUS_CHOICES = (
        (STATUS_PENDING, 'قيد المراجعة'),
        (STATUS_PAID, 'تم التحويل'),
        (STATUS_REJECTED, 'مرفوض'),
    )
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='withdrawals')
    amount = models.DecimalField(max_digits=10, decimal_places=2, verbose_name="╪º┘ä┘à╪¿┘ä╪║ ╪º┘ä┘à╪╖┘ä┘ê╪¿")
    method = models.CharField(max_length=20, choices=METHODS, verbose_name="╪╖╪▒┘è┘é╪⌐ ╪º┘ä╪│╪¡╪¿")
    details = models.TextField(verbose_name="╪¿┘è╪º┘å╪º╪¬ ╪º┘ä╪¬╪¡┘ê┘è┘ä (╪▒┘é┘à/╪¡╪│╪º╪¿)")
    is_paid = models.BooleanField(default=False, verbose_name="╪¬┘à ╪º┘ä╪¬╪¡┘ê┘è┘ä")
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        db_index=True,
        verbose_name="حالة الطلب",
    )
    rejection_reason = models.TextField(blank=True, default='', verbose_name="سبب الرفض")
    reviewed_at = models.DateTimeField(null=True, blank=True, verbose_name="تاريخ المراجعة")

    def save(self, *args, **kwargs):
        if self.is_paid and self.status == self.STATUS_PENDING:
            self.status = self.STATUS_PAID
        if self.status == self.STATUS_PAID:
            self.is_paid = True
        else:
            self.is_paid = False

        if self.status in (self.STATUS_PAID, self.STATUS_REJECTED) and self.reviewed_at is None:
            self.reviewed_at = timezone.now()

        update_fields = kwargs.get('update_fields')
        if update_fields is not None:
            fields_set = set(update_fields)
            if fields_set & {'status', 'is_paid'}:
                fields_set.update({'status', 'is_paid', 'reviewed_at'})
                kwargs['update_fields'] = list(fields_set)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.amount} - {self.get_method_display()} ({self.get_status_display()})"


class GroupChatMessage(models.Model):
    """رسائل الشات الجماعي الموحد بين طلاب ومعلم المجموعة."""
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='chat_messages')
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='group_chat_messages',
    )
    body = models.TextField(max_length=2000, verbose_name='نص الرسالة')
    is_pinned = models.BooleanField(default=False, verbose_name='رسالة مثبتة')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['created_at', 'id']
        indexes = [
            models.Index(fields=['group', 'created_at']),
        ]

    def __str__(self):
        return f"GroupChat#{self.id} (G{self.group_id} U{self.sender_id})"
