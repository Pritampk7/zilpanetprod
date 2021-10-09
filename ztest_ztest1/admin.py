from django.contrib import admin

# Register your models here.

from .models import cisco_output,ipaddress,hostDetails

admin.site.register(cisco_output)
admin.site.register(ipaddress)
admin.site.register(hostDetails)