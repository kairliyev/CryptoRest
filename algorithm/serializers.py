from django.contrib.auth.models import User
from rest_framework import serializers
from algorithm.models import *


class AlgorithmListSerializers(serializers.ModelSerializer):
    class Meta:
        model = AlgorithmTypes
        fields = '__all__'


class CipherSerializers(serializers.ModelSerializer):

    class Meta:
        model = CipherInstructions
        fields = '__all__'
