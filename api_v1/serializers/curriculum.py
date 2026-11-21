"""api_v1.serializers.curriculum
Extracted from api_v1/serializers.py.
"""

from rest_framework import serializers
from core.models import (
    CurriculumUnit,
    CurriculumLesson,
)


class CurriculumLessonSerializer(serializers.ModelSerializer):
    class Meta:
        model = CurriculumLesson
        fields = ['id', 'title', 'order']


class CurriculumUnitSerializer(serializers.ModelSerializer):
    lessons = CurriculumLessonSerializer(many=True, read_only=True)
    subject_name = serializers.CharField(source='subject.name', read_only=True)
    grade_display = serializers.CharField(source='get_grade_display', read_only=True)
    term_display = serializers.CharField(source='get_term_display', read_only=True)

    class Meta:
        model = CurriculumUnit
        fields = [
            'id', 'title', 'subject', 'subject_name',
            'grade', 'grade_display', 'term', 'term_display',
            'order', 'lessons',
        ]
