import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ta3alm_project.settings')
django.setup()

from core.models import Subject, CurriculumUnit, CurriculumLesson

def import_data(data):
    for item in data:
        grade = item['grade']
        term = item['term']
        subject_name = item['subject']
        
        subject, _ = Subject.objects.get_or_create(name=subject_name)
        
        for unit_data in item.get('units', []):
            unit, _ = CurriculumUnit.objects.get_or_create(
                title=unit_data['title'],
                subject=subject,
                grade=grade,
                term=term,
                defaults={'order': unit_data.get('order', 1)}
            )
            for lesson_data in unit_data.get('lessons', []):
                CurriculumLesson.objects.get_or_create(
                    unit=unit,
                    title=lesson_data['title'],
                    defaults={'order': lesson_data.get('order', 1)}
                )
        print(f"Finished {grade} - {term} - {subject_name}")

data = [
    # الصف الثاني الإعدادي - الترم الأول
    {
        "grade": "2_prep", "term": "1", "subject": "اللغة العربية",
        "units": [
            {"title": "الوحدة الأولى: قيم إسلامية", "order": 1, "lessons": [
                {"title": "قراءة: كبرياء طفل", "order": 1},
                {"title": "نص: نصائح غالية (قرآن كريم)", "order": 2},
                {"title": "نحو: الإعراب والبناء", "order": 3}
            ]},
            {"title": "الوحدة الثانية: من أجل مصر", "order": 2, "lessons": [
                {"title": "قراءة: لو أنني ضابط شرطة", "order": 1},
                {"title": "نص: من أجل مصر (حديث شريف)", "order": 2},
                {"title": "نص: في حب مصر", "order": 3},
                {"title": "نحو: النعت", "order": 4}
            ]},
            {"title": "الوحدة الثالثة: جيش مصر المنتصر", "order": 3, "lessons": [
                {"title": "قراءة: منتصر ومجاهد", "order": 1},
                {"title": "قراءة: طيار مقاتل مرة أخرى", "order": 2},
                {"title": "نص: سيناء أرض الفيروز", "order": 3},
                {"title": "نحو: العطف", "order": 4}
            ]}
        ]
    },
    {
        "grade": "2_prep", "term": "1", "subject": "العلوم",
        "units": [
            {"title": "الوحدة الأولى: دورية العناصر وخواصها", "order": 1, "lessons": [
                {"title": "محاولات تصنيف العناصر", "order": 1},
                {"title": "تدرج خواص العناصر في الجدول الدوري الحديث", "order": 2},
                {"title": "المجموعات الرئيسية بالجدول الدوري الحديث", "order": 3},
                {"title": "الماء", "order": 4}
            ]},
            {"title": "الوحدة الثانية: الغلاف الجوي وحماية كوكب الأرض", "order": 2, "lessons": [
                {"title": "طبقات الغلاف الجوي", "order": 1},
                {"title": "تآكل طبقة الأوزون وارتفاع درجة حرارة الأرض", "order": 2}
            ]},
            {"title": "الوحدة الثالثة: الحفريات وحماية الأنواع من الانقراض", "order": 3, "lessons": [
                {"title": "الحفريات", "order": 1},
                {"title": "الانقراض", "order": 2}
            ]}
        ]
    },
    {
        "grade": "2_prep", "term": "1", "subject": "الرياضيات",
        "units": [
            {"title": "الوحدة الأولى: الأعداد الحقيقية (جبر)", "order": 1, "lessons": [
                {"title": "الجذر التكعيبي للعدد النسبي", "order": 1},
                {"title": "مجموعة الأعداد غير النسبية", "order": 2},
                {"title": "مجموعة الأعداد الحقيقية وعلاقة الترتيب في ح", "order": 3},
                {"title": "الفترات", "order": 4},
                {"title": "العمليات على الأعداد الحقيقية", "order": 5}
            ]},
            {"title": "الوحدة الثانية: العلاقة بين متغيرين", "order": 2, "lessons": [
                {"title": "العلاقة بين متغيرين", "order": 1},
                {"title": "ميل الخط المستقيم", "order": 2}
            ]},
            {"title": "الوحدة الرابعة: متوسطات المثلث (هندسة)", "order": 4, "lessons": [
                {"title": "متوسطات المثلث", "order": 1},
                {"title": "المثلث المتساوي الساقين", "order": 2}
            ]}
        ]
    },
    # الصف الثالث الإعدادي - الترم الأول
    {
        "grade": "3_prep", "term": "1", "subject": "اللغة العربية",
        "units": [
            {"title": "الوحدة الأولى: حقوق وواجبات", "order": 1, "lessons": [
                {"title": "قراءة: قصة أثر", "order": 1},
                {"title": "نص: عباد الرحمن", "order": 2},
                {"title": "نص: كن جميلا", "order": 3},
                {"title": "نحو: المنادى", "order": 4}
            ]},
            {"title": "الوحدة الثانية: رحلة إلى الفضاء", "order": 2, "lessons": [
                {"title": "قراءة: سميرة موسى", "order": 1},
                {"title": "قراءة: زراعة الفضاء", "order": 2},
                {"title": "نص: رحمة ومحبة", "order": 3},
                {"title": "نحو: البدل", "order": 4}
            ]}
        ]
    },
    {
        "grade": "3_prep", "term": "1", "subject": "العلوم",
        "units": [
            {"title": "الوحدة الأولى: القوى والحركة", "order": 1, "lessons": [
                {"title": "الحركة في اتجاه واحد", "order": 1},
                {"title": "التمثيل البياني للحركة في خط مستقيم", "order": 2},
                {"title": "الكميات الفيزيائية القياسية والمتجهة", "order": 3}
            ]},
            {"title": "الوحدة الثانية: الطاقة الضوئية", "order": 2, "lessons": [
                {"title": "المرايا", "order": 1},
                {"title": "العدسات", "order": 2}
            ]},
            {"title": "الوحدة الثالثة: الكون والنظام الشمسي", "order": 3, "lessons": [
                {"title": "الكون والنظام الشمسي", "order": 1}
            ]},
            {"title": "الوحدة الرابعة: التكاثر واستمرار النوع", "order": 4, "lessons": [
                {"title": "الانقسام الخلوي", "order": 1},
                {"title": "التكاثر اللاجنسي والتكاثر الجنسي", "order": 2}
            ]}
        ]
    },
    {
        "grade": "3_prep", "term": "1", "subject": "الرياضيات",
        "units": [
            {"title": "الوحدة الأولى: العلاقات والدوال (جبر)", "order": 1, "lessons": [
                {"title": "حاصل الضرب الديكارتي", "order": 1},
                {"title": "العلاقات", "order": 2},
                {"title": "الدوال (التطبيقات)", "order": 3},
                {"title": "دوال كثيرات الحدود", "order": 4}
            ]},
            {"title": "الوحدة الثانية: النسبة والتناسب (جبر)", "order": 2, "lessons": [
                {"title": "النسبة", "order": 1},
                {"title": "التناسب", "order": 2}
            ]},
            {"title": "الوحدة الرابعة: حساب المثلثات", "order": 4, "lessons": [
                {"title": "النسب المثلثية الأساسية للزاوية الحادة", "order": 1},
                {"title": "النسب المثلثية الأساسية لبعض الزوايا", "order": 2}
            ]}
        ]
    }
]

if __name__ == '__main__':
    import_data(data)
