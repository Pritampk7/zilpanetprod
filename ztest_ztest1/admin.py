from django.contrib import admin

# Register your models here.

from .models import cisco_output,ipaddress,hostDetails,ciscoConfig, cisco_config_result

admin.site.register(cisco_output)
admin.site.register(ipaddress)
admin.site.register(hostDetails)
admin.site.register(ciscoConfig)
admin.site.register(cisco_config_result)