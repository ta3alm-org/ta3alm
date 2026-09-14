import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ta3alm_project.settings')
django.setup()

from core.models import Subject, CurriculumUnit, CurriculumLesson

def import_data(file_name):
    data = json.load(open(file_name, encoding='utf-8'))
    for item in data:
        grade = item['grade']
        term_raw = item['term']
        term = '1' if '1' in term_raw else '2'
        subject_name = item['subject']
        
        subject, _ = Subject.objects.get_or_create(name=subject_name)
        
        for unit_data in item.get('units', []):
            print(f"Creating unit: {unit_data['title']}")
            unit, _ = CurriculumUnit.objects.get_or_create(
                title=unit_data['title'],
                subject=subject,
                grade=grade,
                term=term,
                defaults={'order': unit_data.get('order', 1)}
            )
            for lesson_data in unit_data.get('lessons', []):
                print(f"  Creating lesson: {lesson_data['title']}")
                CurriculumLesson.objects.get_or_create(
                    unit=unit,
                    title=lesson_data['title'],
                    defaults={'order': lesson_data.get('order', 1)}
                )
        print(f"Finished {grade} - {term} - {subject_name}")

if __name__ == '__main__':
    import sys
    import_data(sys.argv[1])
