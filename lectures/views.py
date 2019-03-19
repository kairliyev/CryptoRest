from django.shortcuts import render

from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny


from lectures.models import Lecture
from lectures.serializers import  LectureSerializer, LectureListSerial


class LectureList(ListCreateAPIView):
    serializer_class = LectureListSerial

    def get_queryset(self):
        return Lecture.objects.all()


class LectureDetail(RetrieveUpdateDestroyAPIView):
    serializer_class = LectureSerializer

    def get_object(self):
        return Lecture.objects.get(id=self.kwargs['pk'])
