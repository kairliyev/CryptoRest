from django.urls import path
from lectures.views import *

app_name = 'lectures'

urlpatterns = [
    path('list/', LectureList.as_view(), name="list"),
    path('list/<int:pk>/', LectureDetail.as_view(), name="detail"),

]