"""ztest_mode1 URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from ztest_ztest1 import views as view
urlpatterns = [
    path('admin/', admin.site.urls),
    path('fetchConfigData/', view.fetchConfigDetail),
    path('ipAddress/<int:pk>', view.get_update_delete_entry),
    path('ciscoOutput/', view.cisco_result),
    path('ciscoOutput/<int:pk>', view.delete_from_db),
    path('getDeviceCreds/', view.getDeviceCredentials),
    path('getDeviceCreds/<int:pk>', view.update_credentials),
    path('hostName/', view.ipList),
    path('hostDetail/', view.ipDetail),
    path('hostWithDetail/', view.hostDetail),
    path('hostWithDetail/<int:pk>', view.update_device_details),
]
