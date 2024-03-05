from django.urls import path
from . import views

urlpatterns = [
    path('webpage/', views.homepage, name='webpage'),
]