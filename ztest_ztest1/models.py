from django.db import models


class ipaddress(models.Model):
    ip_address = models.JSONField(null=False, default=dict)

    def __str__(self):
        return self.ip_address


class cisco_output(models.Model):
    cisco_output = models.JSONField(null=False, default=dict)

    def __str__(self):
        return self.cisco_output


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

    def __unicode__(self):
        return self.hostname
