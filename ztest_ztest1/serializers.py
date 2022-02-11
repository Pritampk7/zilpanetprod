from rest_framework import serializers
from .models import ipaddress, cisco_output, device_creds, ipAddressAndHostname, ipWithDetail, hostDetails, ciscoConfig, cisco_config_result


class ip_Serrializers(serializers.ModelSerializer):
    class Meta:
        model = ipaddress
        fields = ['timestamp','ip_address']


class CiscoOut_Serrializers(serializers.ModelSerializer):
    class Meta:
        model = cisco_output
        fields = ['success','timestamp','data']

class credentials_Serrializers(serializers.ModelSerializer):
    class Meta:
        model = device_creds
        fields = ['ipaddressCredentials']

class device_ip_Serrializers(serializers.ModelSerializer):
    class Meta:
        model = ipAddressAndHostname
        fields = ['ip_Address']


class device_detail_Serrializers(serializers.ModelSerializer):
    class Meta:
        model = ipWithDetail
        fields = ['secret', 'username', 'password', 'deviceLocation', 'deviceType', 'hostname', 'ipaddress']


class host_detail_Serrializers(serializers.ModelSerializer):
    class Meta:
        model = hostDetails
        fields = ['secret', 'username', 'password', 'deviceLocation', 'deviceType', 'hostname', 'ipaddress','vendorName']

#this code is for config-cisco
class ciscoConfigData(serializers.ModelSerializer):
    class Meta:
        model = ciscoConfig
        fields = ['success','timestamp','payload']

class CiscoConfigOut_Serrializers(serializers.ModelSerializer):
    class Meta:
        model = cisco_config_result
        fields = ['success','timestamp','data']