import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ta3alm_project.settings')
django.setup()

from core.models import Subject, CurriculumUnit, CurriculumLesson

def generate_curriculum():
    grades = [
        '1_primary', '2_primary', '3_primary', 
        '4_primary', '5_primary', '6_primary',
        '2_prep', '3_prep',
        '1_sec', '2_sec', '3_sec'
    ]
    terms = ['1', '2']
    subjects = ['اللغة العربية', 'الرياضيات', 'العلوم', 'الدراسات الاجتماعية', 'اللغة الإنجليزية']

    for grade in grades:
        for term in terms:
            for subject_name in subjects:
                # Skip science and social studies for primary 1-3
                if grade in ['1_primary', '2_primary', '3_primary'] and subject_name in ['العلوم', 'الدراسات الاجتماعية']:
                    continue
                
                subject, _ = Subject.objects.get_or_create(name=subject_name)
                
                # Create 3 units per subject-term
                for unit_idx in range(1, 4):
                    unit_title = f"الوحدة {unit_idx}"
                    if unit_idx == 1: unit_title = "الوحدة الأولى"
                    elif unit_idx == 2: unit_title = "الوحدة الثانية"
                    elif unit_idx == 3: unit_title = "الوحدة الثالثة"
                    
                    unit, _ = CurriculumUnit.objects.get_or_create(
                        title=unit_title,
                        subject=subject,
                        grade=grade,
                        term=term,
                        defaults={'order': unit_idx}
                    )
                    
                    # Create 4 lessons per unit
                    for lesson_idx in range(1, 5):
                        lesson_title = f"الدرس {lesson_idx}"
                        if lesson_idx == 1: lesson_title = "الدرس الأول"
                        elif lesson_idx == 2: lesson_title = "الدرس الثاني"
                        elif lesson_idx == 3: lesson_title = "الدرس الثالث"
                        elif lesson_idx == 4: lesson_title = "الدرس الرابع"
                        
                        CurriculumLesson.objects.get_or_create(
                            unit=unit,
                            title=lesson_title,
                            defaults={'order': lesson_idx}
                        )
                print(f"Generated data for {grade} - Term {term} - {subject_name}")
    print("All generic curriculum generated successfully!")

if __name__ == '__main__':
    generate_curriculum()
