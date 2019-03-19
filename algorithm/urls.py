from django.urls import path
from algorithm.views import *

app_name = 'algorithm'

urlpatterns = [
    path('sym/', algorithmsymmetric, name="symmetric"),
    path('assym/rsa', algorithmassymetric_rsa, name="rsa"),
    path ('list/', AlgorithmList.as_view(), name="list"),
    # path('unsym/', LectureList.as_view(), name="list"),
    path('list/<int:pk>/', CipherList.as_view(), name="detail"),
]