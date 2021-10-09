from django.db import models
import time

class ipaddress(models.Model):
    timestamp = models.CharField(null=False, default=time.time(), max_length=30)
    ip_address = models.JSONField(null=False, default=dict)  

    def __unicode__(self):
        return self.ip_address if self.ip_address else ''


class cisco_output(models.Model):
    data = models.JSONField(null=False, default=dict)
    timestamp = models.CharField(null=False, default="20", max_length=25)
    success = models.CharField(null=False, default="True", max_length=10)


class device_creds(models.Model):
    ipaddressCredentials = models.JSONField(null=False, default=dict)

    def __str__(self):
        return self.ipaddressCredentials


class ipAddressAndHostname(models.Model):
    ip_Address = models.JSONField(null=False, default=dict)

    def __str__(self):
        return self.ip_Address

class ipWithDetail(models.Model):
    ipaddress = models.CharField(max_length=25, unique=True)
    hostname = models.ForeignKey(ipAddressAndHostname, related_name='ipaddress', on_delete=models.CASCADE)
    secret = models.CharField(max_length=25)
    username = models.CharField(max_length=25)
    password = models.CharField(max_length=25)
    deviceLocation = models.CharField(max_length=25)
    deviceType = models.CharField(max_length=25)

    def __unicode__(self):
        return self.ipaddress

class hostDetails(models.Model):
    ipaddress = models.CharField(max_length=25,unique=True)
    hostname = models.CharField(max_length=25)
    secret = models.CharField(max_length=25)
    username = models.CharField(max_length=25)
    password = models.CharField(max_length=25)
    deviceLocation = models.CharField(max_length=25)
    deviceType = models.CharField(max_length=25)
    vendorName = models.CharField(max_length=25)

    def __str__(self):
        return self.ipaddress
