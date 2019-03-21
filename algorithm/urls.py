from django.urls import path
from algorithm.views import *

app_name = 'algorithm'

urlpatterns = [
    path('symmetric/', algorithmsymmetric, name="symmetric"),
    path('assymmetric/', algorithmassymetric, name="assymetric"),
    path('hash/', hash_functions, name="hash"),
    path('basics/', basics, name="basics"),
    # path('basics/vigenere', vigenere, name="vigenere"),
    path ('list/', AlgorithmList.as_view(), name="list"),
    # path('unsym/', LectureList.as_view(), name="list"),
    path('list/<int:pk>/', CipherList.as_view(), name="detail"),
]