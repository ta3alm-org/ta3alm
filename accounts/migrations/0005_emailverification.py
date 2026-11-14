import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_onetimeloginlink'),
    ]

    operations = [
        migrations.CreateModel(
            name='EmailVerification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.UUIDField(default=uuid.uuid4, editable=False, unique=True, verbose_name='رمز التفعيل المباشر')),
                ('code', models.CharField(max_length=6, verbose_name='كود التفعيل')),
                ('is_verified', models.BooleanField(default=False, verbose_name='مُفعّل')),
                ('expires_at', models.DateTimeField(verbose_name='تاريخ انتهاء الصلاحية')),
                ('last_sent_at', models.DateTimeField(blank=True, null=True, verbose_name='آخر وقت إرسال')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='تاريخ الإنشاء')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='email_verification', to=settings.AUTH_USER_MODEL, verbose_name='المستخدم')),
            ],
            options={
                'verbose_name': 'تفعيل البريد الإلكتروني',
                'verbose_name_plural': 'طلبات تفعيل البريد الإلكتروني',
            },
        ),
    ]

