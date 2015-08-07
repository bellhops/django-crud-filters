from rest_framework import serializers

from .models import TestClass


class TestClassSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestClass
        fields = (
            'id',
            'field_one',
            'field_two',
            'field_three',
            'field_four',
            'field_five',
        )
