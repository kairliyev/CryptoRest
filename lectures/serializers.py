from django.contrib.auth.models import User
from rest_framework import serializers
from lectures.models import Lecture


class LectureSerializer(serializers.ModelSerializer):
    class Meta:
        model = Lecture
        fields = '__all__'

class LectureListSerial(serializers.ModelSerializer):
    class Meta:
        model = Lecture
        fields = ('id', 'name', 'rating', 'picture')
