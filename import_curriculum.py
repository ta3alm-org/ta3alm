import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ta3alm_project.settings')
django.setup()

from core.models import Subject, CurriculumUnit, CurriculumLesson

def import_data():
    with open('prompt.txt', 'r', encoding='utf-8') as f:
        data = json.load(f)

    for item in data:
        raw_grade = item.get('grade', '')
        raw_term = item.get('term', '')
        
        # Map grade (prep_1 -> 1_prep)
        grade = raw_grade
        if raw_grade == 'prep_1': grade = '1_prep'
        elif raw_grade == 'prep_2': grade = '2_prep'
        elif raw_grade == 'prep_3': grade = '3_prep'
        elif raw_grade == 'sec_1': grade = '1_sec'
        elif raw_grade == 'sec_2': grade = '2_sec'
        elif raw_grade == 'sec_3': grade = '3_sec'

        # Map term (term_1 -> 1)
        term = '1' if '1' in raw_term else '2'

        subject_name = item['subject']
        
        # التأكد من وجود المادة
        subject, created = Subject.objects.get_or_create(name=subject_name)
        
        # إدخال الوحدات
        for unit_data in item.get('units', []):
            unit, created_unit = CurriculumUnit.objects.get_or_create(
                grade=grade,
                term=term,
                subject=subject,
                title=unit_data['title'],
                defaults={'order': unit_data.get('order', 1)}
            )
            
            # إدخال الدروس
            for lesson_data in unit_data.get('lessons', []):
                CurriculumLesson.objects.get_or_create(
                    unit=unit,
                    title=lesson_data['title'],
                    defaults={'order': lesson_data.get('order', 1)}
                )
        print(f"تم الانتهاء من مادة {subject_name}", flush=True)

    print("تم إدخال المناهج بنجاح!", flush=True)

if __name__ == '__main__':
    import_data()
