from .models import ipaddress, cisco_output, device_creds, ipAddressAndHostname, ipWithDetail, hostDetails
from .serializers import *
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.decorators import api_view

# app level imports
#
import threading
from time import time
import netmiko
import time, json, collections
import xmltodict, json
import requests
from jnpr.junos import Device
from jnpr.junos.utils.start_shell import StartShell
import re
import arubaapi

# exceptions
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetmikoTimeoutException
from netmiko.ssh_exception import NetmikoAuthenticationException
from paramiko.ssh_exception import SSHException


def cisco_ios(cisco_ip, cisco_cmds, username, password, secret):
    display_output = []
    try:
        router = {'ip': cisco_ip,
                  'username': username,
                  'password': password,
                  'device_type': 'cisco_ios',
                  'secret': secret
                  }
        print(f"its hurry with {cisco_ip}")
        session = ConnectHandler(**router)
        session.enable()
        file_ptr = open(f"{cisco_ip}.logs", 'w')
        for cmd in cisco_cmds:
            try:
                output = session.send_command(cmd, use_textfsm=True)
                time.sleep(2)
                if type(output) == list:
                    out_res = {
                        "device": cisco_ip,
                        "command": cmd,
                        "output": output
                    }
                    time.sleep(1)
                    display_output.append(out_res)
                    file_ptr.write(json.dumps(out_res))
                else:
                    json_obj = output.replace('\n', ',').split(',')
                    out_res = {
                        "device": cisco_ip,
                        "command": cmd,
                        "output": [j.rstrip() for j in json_obj if j != '']
                    }
                    new = json.dumps(out_res, indent=4)
                    display_output.append(out_res)
            except:
                router = {'ip': cisco_ip,
                          'username': username,
                          'password': password,
                          'device_type': 'cisco_ios',
                          'secret': secret
                          }
                print("executing this block due to parsing issue")
                print(f"its hurry with {cisco_ip}")
                session = ConnectHandler(**router)
                session.enable()
                output = session.send_command(cmd)
                json_obj = output.replace('\n', ',').split(',')
                out_res = {
                    "device": cisco_ip,
                    "command": cmd,
                    "output": [j.rstrip() for j in json_obj if j != '']
                }
                time.sleep(1)
                display_output.append(out_res)
            with open(f"{cisco_ip}.logs", 'w') as file:
                file.write(json.dumps(out_res, indent=4))

        payload = {"cisco_output": display_output}
        print(type(payload))
        data_flex = json.dumps(display_output, indent=4)
        headers = {"content-type": "application/json"}
        r = requests.post(url="https://127.0.0.1:8000/ciscoOutput/", data=json.dumps(payload), headers=headers)
        print(r.status_code)
        return json.dumps(display_output, indent=4)

    except NetmikoTimeoutException:
        print("the device is unreachable")
        out_res = [{
            "output": {
                "device": cisco_ip,
                "output": "unable to connect to device!!!, Please check the connectivity".upper(),
                "failed": True
            }
        }]
        payload = {"cisco_output": out_res}
        print(payload)
        headers = {"content-type": "application/json"}
        r = requests.post(url="https://127.0.0.1:8000/ciscoOutput/", data=json.dumps(payload), headers=headers)
        print(r.status_code)
        return r.status_code
    except SSHException:
        print(f"SSH might not be configured on {cisco_ip}")

    except EOFError:
        print(f"MAX attempts failed for {cisco_ip}")


@api_view(['GET', 'POST'])
def cisco_result(request):
    if request.method == 'GET':
        students = cisco_output.objects.all()
        serializer = CiscoOut_Serrializers(students, many=True)
        response = list(serializer.data)
        return Response(response)

    if request.method == 'POST':
        serializer = CiscoOut_Serrializers(data=request.data)
        print(serializer)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from django.views.decorators.csrf import ensure_csrf_cookie

@api_view(['GET', 'POST'])
@ensure_csrf_cookie
def fetchConfigDetail(request):
    if request.method == 'GET':
        students = ipaddress.objects.all()
        serializer = ip_Serrializers(students, many=True)
        response = list(serializer.data)
        return Response(response)

    elif request.method == 'POST':
        display_output = []
        serializer = ip_Serrializers(data=request.data)
        if serializer.is_valid():
            serializer.save()
            if request.data["ip_address"]["cisco"]["CiscoCommand"] != [""] and request.data["ip_address"]["cisco"][
                "CiscoIpAddress"] != [""]:
                cisco_cmds = request.data["ip_address"]["cisco"]["CiscoCommand"]
                cisco_ip = request.data["ip_address"]["cisco"]["CiscoIpAddress"]
                print("here cisco")
                cisco_Thedes = []
                for cisco_ip in cisco_ip:
                    dummy_creds = hostDetails.objects.filter(ipaddress=cisco_ip)
                    serializer = host_detail_Serrializers(dummy_creds, many=True)
                    response = dict({cisco_ip: serializer.data})
                    print("##########################")
                    print(response)
                    if not response[cisco_ip]:
                        out_rest = {
                            "device": cisco_ip,
                            "stdout": ["THIS DEVICE IS NOT REGISTERED WITH ZILPANET SOFTWARE"],
                            "failed": True
                        }
                        payload = {"cisco_output": out_rest}
                        headers = {"content-type": "application/json"}
                        r = requests.post(url="https://127.0.0.1:8000/ciscoOutput/", data=json.dumps(payload),
                                          headers=headers)
                        print(r.status_code)
                        return Response(serializer.data, status=status.HTTP_200_OK)
                    username = response[cisco_ip][0]["username"]
                    password = response[cisco_ip][0]["password"]
                    secret = response[cisco_ip][0]["secret"]
                    time.sleep(1)

                    my_thread = threading.Thread(
                        target=cisco_ios,
                        args=(cisco_ip, cisco_cmds, username, password, secret)
                    )
                    my_thread.start()
                    cisco_Thedes.append(my_thread)
                for thread in cisco_Thedes:
                    thread.join()

            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'POST'])
def delete_from_db(request, pk):
    try:
        output = cisco_output.objects.get(pk=pk)
    except cisco_output.DoesNotExists:
        return Response(status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        serializer = CiscoOut_Serrializers(output)
        return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        serializer = CiscoOut_Serrializers(output, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_204_NO_CONTENT)

    if request.method == 'DELETE':
        output.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['GET', 'PUT', 'POST'])
def get_update_delete_entry(request, pk):
    try:
        ip = ipaddress.objects.get(pk=pk)
    except ipaddress.DoesNotExists:
        return Response(status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        serializer = ip_Serrializers(ip)
        return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        serializer = ip_Serrializers(ip, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_204_NO_CONTENT)

    if request.method == 'DELETE':
        ip.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['GET', 'POST'])
def getDeviceCredentials(request):
    if request.method == 'GET':
        students = device_creds.objects.all()
        serializer = credentials_Serrializers(students, many=True)
        response = list(serializer.data)
        return Response(response)

    if request.method == 'POST':
        serializer = credentials_Serrializers(data=request.data)
        print(dict(serializer))
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'POST'])
def update_credentials(request, pk):
    try:
        ip = device_creds.objects.get(pk=pk)
    except ipaddress.DoesNotExists:
        return Response(status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        serializer = credentials_Serrializers(ip)
        return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        serializer = credentials_Serrializers(ip, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_204_NO_CONTENT)

    if request.method == 'DELETE':
        ip.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['GET', 'POST'])
def ipList(request):
    if request.method == 'GET':
        students = ipAddressAndHostname.objects.all()
        serializer = device_ip_Serrializers(students, many=True)
        response = list(serializer.data)
        return Response(response)

    if request.method == 'POST':
        serializer = device_ip_Serrializers(data=request.data)
        print(dict(serializer))
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




@api_view(['GET', 'POST'])
def ipDetail(request):
    if request.method == 'GET':
        students = ipWithDetail.objects.all()
        serializer = device_detail_Serrializers(students, many=True)
        response = list(serializer.data)
        return Response(response)

    if request.method == 'POST':
        serializer = device_detail_Serrializers(data=request.data)
        print(dict(serializer))
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST'])
def hostDetail(request):
    if request.method == 'GET':
        students = hostDetails.objects.filter(vendorName='cisco')
        print(students)
        serializer = host_detail_Serrializers(students, many=True)
        response = list(serializer.data)
        cisco_ips = [i['ipaddress'] for i in response]
        return Response({"ipaddress": {"cisco": cisco_ips}})


    if request.method == 'POST':
        serializer = host_detail_Serrializers(data=request.data)
        if serializer.is_valid():
            serializer.save()
            print(dict(serializer.validated_data))
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'POST'])
def update_device_details(request, pk):
    try:
        ip = hostDetails.objects.get(pk=pk)
        print(ip)
    except ipaddress.DoesNotExists:
        return Response(status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        serializer = host_detail_Serrializers(ip)
        return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        serializer = host_detail_Serrializers(ip, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_204_NO_CONTENT)

    if request.method == 'DELETE':
        ip.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
