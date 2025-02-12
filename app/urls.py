from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('upload', views.upload_pcap, name='upload_pcap'),
    path('analysis', views.analysis, name='analysis')
]
