from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_curriculumunit_curriculumlesson'),
    ]

    operations = [
        migrations.AddField(
            model_name='sitesetting',
            name='platform_commission_percentage',
            field=models.PositiveIntegerField(
                default=20,
                validators=[MinValueValidator(0), MaxValueValidator(100)],
                verbose_name='نسبة عمولة المنصة (%)',
            ),
        ),
    ]

