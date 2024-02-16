from .models import ipaddress, cisco_output, ciscoConfig, device_creds, ipAddressAndHostname, ipWithDetail, hostDetails, cisco_config_result
from .serializers import *
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.decorators import api_view
from setuptools._vendor import more_itertools

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
from netmiko import ConnectHandler, SSHDetect,Netmiko
from netmiko.exceptions import NetmikoTimeoutException
from netmiko.exceptions import NetmikoAuthenticationException
from paramiko.ssh_exception import SSHException

import napalm
def cisco_ios(cisco_ip, cisco_cmds, username, password, secret, timestamp, device_type):
    display_output = []
    try:
        router = {'ip': cisco_ip,
                  'username': username,
                  'password': password,
                  'device_type': device_type,
                  'secret': secret
                  }
        
        print(f"its hurry with {cisco_ip}")

        session = Netmiko(**router)
        session.enable()
        file_ptr = open(f"{cisco_ip}.logs", 'w')
        for cmd in cisco_cmds:
            try:
                output = session.send_command(cmd, use_textfsm=True)
                time.sleep(2)
                if type(output) == list:
                    out_res = {
                        "command": cmd,
                        "output": output
                    }
                    time.sleep(1)
                    display_output.append(out_res)
                    file_ptr.write(json.dumps(out_res))
                else:
                    json_obj = output.replace('\n', ',').split(',')
                    out_res = {
                        
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
                    "command": cmd,
                    "output": [j.rstrip() for j in json_obj if j != '']
                }
                time.sleep(1)
                display_output.append(out_res)
            with open(f"{cisco_ip}.logs", 'w') as file:
                file.write(json.dumps(out_res, indent=4))

        payload = {
            "timestamp": timestamp,
            "data": {
                cisco_ip: display_output
            }
        }
        print(type(payload))
        print(payload)
        headers = {"content-type": "application/json"}       
        r = requests.post(url="https://zilpa-test.herokuapp.com/ciscoOutput/", data=json.dumps(payload), headers=headers, verify=False)
        print(r.status_code)
        return json.dumps(payload, indent=4)

    except NetmikoTimeoutException:     
        print("the device is unreachable")
        out_res = [{
            "output": {
                "device": cisco_ip,
                "output": "unable to connect to device!!!, Please check the connectivity".upper(),
            }
        }]
        display_output.append(out_res)
        payload = {
            "success": "False",
            "timestamp": timestamp,
            "data": {
                cisco_ip: display_output
            }
        }
        print(payload)
        headers = {"content-type": "application/json"}
        r = requests.post(url="https://zilpa-test.herokuapp.com/ciscoOutput/", data=json.dumps(payload), headers=headers,verify=False)
        print(r.status_code)
        return r.status_code
    except SSHException:
        out_res = [{
            "output": {
                "device": cisco_ip,
                "output": "Cannot SSH!!!, Please check the connectivity".upper(),
            }
        }]
        display_output.append(out_res)
        payload = {
            "success": "False",
            "timestamp": timestamp,
            "data": {
                cisco_ip: display_output
            }
        }
        print(payload)
        headers = {"content-type": "application/json"}
        r = requests.post(url="https://zilpa-test.herokuapp.com/ciscoOutput/", data=json.dumps(payload), headers=headers,verify=False)
        print(r.status_code)
        print(f"SSH might not be configured on {cisco_ip}")
        return r.status_code
        

    except EOFError:
        print(f"MAX attempts failed for {cisco_ip}")


@api_view(['GET', 'POST'])
def cisco_result(request):
    if request.method == 'GET':
        timestamp = request.GET.get('timestamp','')
        cisco = cisco_output.objects.filter(timestamp=timestamp)
        serializer = CiscoOut_Serrializers(cisco, many=True)
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
class Juniper:

    def get_system_arp(self, connect):
        output = connect.get_arp_table()
        return output

    def get_system_details(self, connect):
        output = connect.get_facts()
        return output

    def interfaces(self, connect):
        output = connect.get_interfaces()
        return output

    def get_vlan_details(self, connect):
        output = connect.get_vlans()
        return output

    def get_bgp_configuration(self, connect):
        output = connect.get_bgp_config()
        return output

    def get_bgp_neighbors(self, connect):
        output = connect.get_bgp_neighbors()
        return output

    def get_bgp_neighbors_detail(self, connect):
        output = connect.get_bgp_neighbors_detail()
        return output

    def get_environment_details(self, connect):
        output = connect.get_environment()
        return output

    def get_interfaces_counters_details(self, connect):
        output = connect.get_interfaces_counters()
        return output

    def get_interfaces_ip(self, connect):
        output = connect.get_interfaces_ip()
        return output

    def get_ipv6_neighbors_table(self, connect):
        output = connect.get_ipv6_neighbors_table()
        return output

    def get_lldp_neighbors(self, connect):
        output = connect.get_lldp_neighbors()
        return output

    def get_lldp_neighbors_detail(self, connect):
        output = connect.get_lldp_neighbors_detail()
        return output

    def get_mac_address_table(self, connect):
        output = connect.get_mac_address_table()
        return output

    def get_network_instances(self, connect):
        output = connect.get_network_instances()
        return output

    def get_ntp_peers(self, connect):
        output = connect.get_ntp_peers()
        return output

    def get_ntp_servers(self, connect):
        output = connect.get_ntp_peers()
        return output

    def get_ntp_stats(self, connect):
        output = connect.get_ntp_stats()
        return output

    def get_probes_config(self, connect):
        output = connect.get_probes_config()
        return output

    def get_optics(self, connect):
        output = connect.get_optics() #test
        return output

    def get_probes_results(self, connect):
        output = connect.get_probes_results()
        return output

    def get_snmp_information(self, connect):
        output = connect.get_snmp_information()
        return output

    def jsonify(self, command, data):
        data_dict = {
            "command": command,
            "output": data
        }
        return data_dict

    def connection(self, ipaddress, commands, username, password, timestamp):

        import napalm
        driver_ios = napalm.get_network_driver("junos")
        print("connected to junos")
        connect = driver_ios(hostname=ipaddress, username=username, password=password,
                             optional_args={'secret': 'G0t2BTuf'})

        connect.open()

        display_output = []

        if "get_arp" in commands:
            data = self.get_system_arp(connect=connect)
            jsonify = self.jsonify(command="get_arp", data=data)
            display_output.append(jsonify)

        if "get_device_details" in commands:
            data = self.get_system_details(connect=connect)
            jsonify = self.jsonify(command="get_device_details", data=data)
            display_output.append(jsonify)

        if "interfaces" in commands:
            data = self.interfaces(connect=connect)
            jsonify = self.jsonify(command="get_device_details", data=data)
            display_output.append(jsonify)

        if "get_vlans" in commands:
            data = self.get_vlan_details(connect=connect)
            jsonify = self.jsonify(command="get_vlans", data=data)
            display_output.append(jsonify)

        if "bgp_configuration" in commands:
            data = self.get_bgp_configuration(connect=connect)
            jsonify = self.jsonify(command="bgp_configuration", data=data)
            display_output.append(jsonify)

        if "bgp_neighbors" in commands:
            data = self.get_bgp_neighbors(connect=connect)
            jsonify = self.jsonify(command="get_bgp_neighbors", data=data)
            display_output.append(jsonify)

        if "bgp_neighbors_details" in commands:
            data = self.get_bgp_neighbors_detail(connect=connect)
            jsonify = self.jsonify(command="get_bgp_neighbors_detail", data=data)
            display_output.append(jsonify)

        if "get_environment_details" in commands:
            data = self.get_environment_details(connect=connect)
            jsonify = self.jsonify(command="get_environment_details", data=data)
            display_output.append(jsonify)
        #
        if "get_interfaces_counters_details" in commands:
            data = self.get_interfaces_counters_details(connect=connect)
            jsonify = self.jsonify(command="get_interfaces_counters_details", data=data)
            display_output.append(jsonify)

        if "get_interfaces_ip" in commands:
            data = self.get_interfaces_ip(connect=connect)
            jsonify = self.jsonify(command="get_interfaces_ip", data=data)
            display_output.append(jsonify)

        if "get_ipv6_neighbors_table" in commands:
            data = self.get_ipv6_neighbors_table(connect=connect)
            jsonify = self.jsonify(command="get_ipv6_neighbors_table", data=data)
            display_output.append(jsonify)

        if "get_network_instances" in commands:
            data = self.get_network_instances(connect=connect)
            jsonify = self.jsonify(command="get_network_instances", data=data)
            display_output.append(jsonify)

        if "get_lldp_neighbors" in commands:
            data = self.get_lldp_neighbors(connect=connect)
            jsonify = self.jsonify(command="get_lldp_neighbors", data=data)
            display_output.append(jsonify)

        if "get_ntp_peers" in commands:
            data = self.get_ntp_peers(connect=connect)
            jsonify = self.jsonify(command="get_ntp_peers", data=data)
            display_output.append(jsonify)

        if "get_mac_address_table" in commands:
            data = self.get_mac_address_table(connect=connect)
            jsonify = self.jsonify(command="get_mac_address_table", data=data)
            display_output.append(jsonify)

        if "get_ntp_servers" in commands:
            data = self.get_ntp_servers(connect=connect)
            jsonify = self.jsonify(command="get_ntp_servers", data=data)
            display_output.append(jsonify)

        if "get_ntp_stats" in commands:
            data = self.get_ntp_stats(connect=connect)
            jsonify = self.jsonify(command="get_ntp_stats", data=data)
            display_output.append(jsonify)

        if "get_optics" in commands:
            data = self.get_optics(connect=connect)
            jsonify = self.jsonify(command="get_optics", data=data)
            display_output.append(jsonify)

        if "get_probes_config" in commands:
            data = self.get_probes_config(connect=connect)
            jsonify = self.jsonify(command="get_probes_config", data=data)
            display_output.append(jsonify)

        if "get_probes_results" in commands:
            data = self.get_probes_results(connect=connect)
            jsonify = self.jsonify(command="get_probes_results", data=data)
            display_output.append(jsonify)

        if "get_snmp_information" in commands:
            data = self.get_snmp_information(connect=connect)
            jsonify = self.jsonify(command="get_snmp_information", data=data)
            display_output.append(jsonify)

        payload = {
            "timestamp": timestamp,
            "data": {
                ipaddress: list(display_output)
            }
        }
        headers = {"content-type": "application/json"}
        r = requests.post(url="http://127.0.0.1:8000/ciscoOutput/", data=json.dumps(payload), headers=headers,
                          verify=False)

        print("write status", r.status_code)

        print(json.dumps(payload, indent=4))

        connect.close()

    def establish_connection(self, juniper_ip, commands, timestamp):
        juniper_Threads = []
        print("here in establish connection")

        for juniper_ip in juniper_ip:
            dummy_creds = hostDetails.objects.filter(ipaddress=juniper_ip)
            serializer = host_detail_Serrializers(dummy_creds, many=True)
            response = dict({juniper_ip: serializer.data})
            print(response)
            if not response[juniper_ip]:
                out_res = {
                    "stdout": ["This device is unregistered to zilpanet".upper()],
                    "failed": True
                }
                payload = {
                    "success": False,
                    "timestamp": timestamp,
                    "data": {
                        juniper_ip: out_res
                    }
                }
                headers = {"content-type": "application/json"}
                r = requests.post(url="http://127.0.0.1:8000/ciscoOutput/", data=json.dumps(payload),
                                  verify=False,
                                  headers=headers)
                print(r.status_code)
                return Response(serializer.data, status=status.HTTP_200_OK)
            username = response[juniper_ip][0]["username"]
            password = response[juniper_ip][0]["password"]
            time.sleep(1)
            print(ipaddress)

            my_thread = threading.Thread(target=self.connection,
                                         args=(juniper_ip,
                                               commands,
                                               username,
                                               password,
                                               timestamp,

                                               )
                                         )
            my_thread.start()
            juniper_Threads.append(my_thread)
        for thread in juniper_Threads:
            thread.join()

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
            print("serializer",serializer.data)
            if request.data["ip_address"]["cisco"]["command"] and request.data["ip_address"]["cisco"][
                "ipAddress"] :
                cisco_cmds = request.data["ip_address"]["cisco"]["command"]
                cisco_ip = request.data["ip_address"]["cisco"]["ipAddress"]

                print("here cisco")
                cisco_Thedes = []
                for cisco_ip in cisco_ip:
                    dummy_creds = hostDetails.objects.filter(ipaddress=cisco_ip)
                    serializer = host_detail_Serrializers(dummy_creds, many=True)
                    response = dict({cisco_ip: serializer.data})    
                    print(response)            
                    if  not response[cisco_ip]:
                       
                        out_rest = {
                            "device": cisco_ip,
                            "stdout": ["THIS DEVICE IS NOT REGISTERED WITH ZILPANET SOFTWARE"],
                            "failed": True
                        }
                        payload = {"cisco_output": out_rest}
                        headers = {"content-type": "application/json"}
                        r = requests.post(url="https://zilpa-test.herokuapp.com/ciscoOutput/", data=json.dumps(payload), verify=False,
                                            headers=headers)
                        print(r.status_code)
                        return Response(serializer.data, status=status.HTTP_200_OK)
                    username = response[cisco_ip][0]["username"]
                    password = response[cisco_ip][0]["password"]
                    secret = response[cisco_ip][0]["secret"]
                    device_type = response[cisco_ip][0]["deviceType"]
                    print(device_type)
                    time.sleep(1)
                   
                    
                    timestamp= request.data["timestamp"]
                    my_thread = threading.Thread(
                        target=cisco_ios,
                        args=(cisco_ip, cisco_cmds, username, password, secret,timestamp,device_type)
                    )
                    my_thread.start()
                    cisco_Thedes.append(my_thread)
                for thread in cisco_Thedes:
                    thread.join()

            if "juniper" in request.data["ip_address"].keys():
                junos_commands = request.data["ip_address"]["juniper"]["command"]
                juniper_ip = request.data["ip_address"]["juniper"]["ipAddress"]

                print("here juniper")
                cisco_Thedes = []
                for juniper_ip in juniper_ip:
                    dummy_creds = hostDetails.objects.filter(ipaddress=juniper_ip)
                    serializer = host_detail_Serrializers(dummy_creds, many=True)
                    response = dict({juniper_ip: serializer.data})                
                    if not response[juniper_ip]:
                       
                        out_rest = {
                            "device": juniper_ip,
                            "stdout": [f"THIS DEVICE {juniper_ip} IS NOT REGISTERED WITH ZILPANET SOFTWARE"],
                            "failed": True
                        }
                        payload = {"cisco_output": out_rest}
                        headers = {"content-type": "application/json"}
                        r = requests.post(url="https://zilpa-test.herokuapp.com/ciscoOutput/", data=json.dumps(payload), verify=False,
                                            headers=headers)
                        print(r.status_code)
                        return Response(serializer.data, status=status.HTTP_200_OK)
                    print("pass")
                    username = response[juniper_ip][0]["username"]
                    password = response[juniper_ip][0]["password"]
                    secret = response[juniper_ip][0]["secret"]
                    timestamp= request.data["timestamp"]
                    junos_commands = request.data["ip_address"]["juniper"]["command"]  # aruba commands
                    juniper_ip = request.data["ip_address"]["juniper"]["ipAddress"]  # aruba ip address
                    juniper_obj = Juniper()
                    juniper_obj.establish_connection(juniper_ip, junos_commands, timestamp)
                   
                    
                    timestamp= request.data["timestamp"]
        return Response(data={"timestamp":timestamp}, status=status.HTTP_200_OK)
    else:
        return Response(request.errors, status=status.HTTP_400_BAD_REQUEST)


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
        cisco_devices = hostDetails.objects.filter(vendorName='cisco')    
        cisco_devices_serializer = host_detail_Serrializers(cisco_devices, many=True)
        cisco_response = list(cisco_devices_serializer.data)
        cisco_ips = [i['ipaddress'] for i in cisco_response]
        juniper_devices = hostDetails.objects.filter(vendorName='juniper')
        juniper_devices_serializer = host_detail_Serrializers(juniper_devices, many=True)
        juniper_response = list(juniper_devices_serializer.data)
        juniper_ips = [i['ipaddress'] for i in juniper_response]

        aruba_devices = hostDetails.objects.filter(vendorName='aruba')
        aruba_devices_serializer = host_detail_Serrializers(aruba_devices, many=True)
        aruba_response = list(aruba_devices_serializer.data)
        aruba_ips = [i['ipaddress'] for i in aruba_response]
        return Response(
            {
                "ipaddress": 
                {
                    "Cisco": cisco_ips,
                    "Juniper": juniper_ips,
                    "Aruba": aruba_ips
                }
                },status=status.HTTP_200_OK)

    if request.method == 'POST':
        register_device = host_detail_Serrializers(data=request.data)
        print(register_device)
        if register_device.is_valid():
            register_device.save()
            return Response(register_device.data, status=status.HTTP_200_OK)
        else:
            return Response(register_device.errors, status=status.HTTP_400_BAD_REQUEST)


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

#this function is for configuring cisco devices
def cisco_ios_config(cisco_ip, config_data, username, password, secret,timestamp, devicetype):
    display_output = []
    print("connected to : ",cisco_ip)
    router = {
        "host": cisco_ip,
        "username": username,
        "password": password,
        "device_type": devicetype,
        "secret": secret
    }
    print(config_data)
    for config_name, config_commnds in config_data.items():
        connect = ConnectHandler(**router)
        connect.enable()
        command = connect.send_config_set(config_commnds)
        
        try:
            if "% Invalid input detected at '^' marker." not in command:
                output = {  
                    "template": config_name,
                    "command": config_commnds,
                    "success": True,
                    "cli_log": command.strip("").split("\n")
                }
                display_output.append(output)

            else:
                output = {
                    "template": config_name,
                    "command": config_commnds,
                    "success": False,
                    "cli_log": command.strip("").split("\n")
                }
                display_output.append(output)
        except:
            output = {
                    "template": config_name,
                    "command": config_commnds,
                    "success": False,
                    "msg": f"device {cisco_ip} not reachable"
                }
            display_output.append(output)

        payload = {
            "success": str(output["success"]),
            "timestamp": timestamp,           
            "data": {
                cisco_ip: display_output
            }
        }
        #print(payload)
        #print(json.dumps(payload))
        # #data_flex = json.dumps(display_output, indent=4)
        headers = {"content-type": "application/json"}
        r = requests.post(url="https://zilpa-test.herokuapp.com/ciscoConfigOutput/", data=json.dumps(payload), headers=headers, verify=False)
        print(r.status_code)
        return json.dumps(payload, indent=4)

def junos_ios_config(cisco_ip, config_data, username, password, secret,timestamp):
    display_output = []
    print("connected to : ",cisco_ip)
    driver_ios = napalm.get_network_driver("junos")
    print("connected to junos")
    connect = driver_ios(hostname="192.168.137.49", username="root", password="root123",
                     )
    connect.open()
    config_data = ['set access radius-server 10.192.168.10 secret abcd@1234']
    for cmd in config_data:
        print(cmd)
        connect.commit_config()
        command = connect.load_merge_candidate(config= cmd)
        connect.commit_config()
        connect.close()
        print("kree")
        
        
        # if "% Invalid input detected at '^' marker." not in command:
        #     output = {  
        #         "template": "config_name",
        #         "command": cmd,
        #         "success": True,
        #         "cli_log": command.strip("").split("\n")
        #     }
        #     display_output.append(output)

        # else:
        #     output = {
        #         "template": "config_name",
        #         "command": cmd,
        #         "success": False,
        #         "cli_log": command.strip("").split("\n")
        #     }
        #     display_output.append(output)

        # payload = {
        #     "success": str(output["success"]),
        #     "timestamp": timestamp,           
        #     "data": {
        #         cisco_ip: display_output
        #     }
        # }
        # #print(payload)
        # #print(json.dumps(payload))
        # # #data_flex = json.dumps(display_output, indent=4)
        # headers = {"content-type": "application/json"}
        # r = requests.post(url="http://127.0.0.1:8000/ciscoConfigOutput/", data=json.dumps(payload), headers=headers, verify=False)
        # print(r.status_code)
        # return json.dumps(payload, indent=4)

@api_view(["GET","POST"])
def ciscoConfigConsole(request):
    if request.method == 'GET':
        getData = ciscoConfig.objects.all()
        serializer = ciscoConfigData(getData, many=True)
        response = list(serializer.data)
        return Response(response)

    if request.method == 'POST':
        serializer = ciscoConfigData(data=request.data)
        if serializer.is_valid():
            serializer.save()
            
            if "cisco" in request.data["payload"]:
                config_data_= request.data["payload"]["cisco"]["configData"]
                config_data= {}
                for i,j in config_data_.items():
                    data1 = [i.split("\n") for i in j]
                    data = list(more_itertools.collapse(data1))
                    config_data[i]= data
                print("*************", json.dumps(config_data))
                cisco_ip = request.data["payload"]["cisco"]["CiscoIpAddress"]

                cisco_Thedes = []
                
                for cisco_ip in cisco_ip:
                    cisco_creds = hostDetails.objects.filter(ipaddress=cisco_ip)
                    serializer = host_detail_Serrializers(cisco_creds, many=True)
                    response = dict({cisco_ip: serializer.data})
                    username = response[cisco_ip][0]["username"]
                    password = response[cisco_ip][0]["password"]
                    secret = response[cisco_ip][0]["secret"]             
                    timestamp= request.data["timestamp"]
                    devicetype= response[cisco_ip][0]["deviceType"]
                    my_thread = threading.Thread(
                            target=cisco_ios_config,
                            args=(cisco_ip, config_data, username, password, secret,timestamp, devicetype)
                        )
                    my_thread.start()
                    cisco_Thedes.append(my_thread)
                for thread in cisco_Thedes:
                    thread.join()

            elif  request.data["payload"]["juniper"].keys():
                print("juniper")
                config_data_= request.data["payload"]["juniper"]["configData"]
                config_data= {}
                for i,j in config_data_.items():
                    data1 = [i.split("\n") for i in j]
                    data = list(more_itertools.collapse(data1))
                    config_data[i]= data
                print("*************", json.dumps(config_data))
                juniper_ip = request.data["payload"]["juniper"]["JuniperIpAddress"]

                juniper_Thedes = []
                
                for juniper_ip in juniper_ip:
                    cisco_creds = hostDetails.objects.filter(ipaddress=juniper_ip)
                    serializer = host_detail_Serrializers(cisco_creds, many=True)
                    response = dict({juniper_ip: serializer.data})
                    username = response[juniper_ip][0]["username"]
                    password = response[juniper_ip][0]["password"]
                    secret = response[juniper_ip][0]["secret"]             
                    timestamp= request.data["timestamp"]
                    print("reacged")
                    my_thread = threading.Thread(
                            target=junos_ios_config,
                            args=(juniper_ip, config_data, username, password, secret,timestamp)
                        )
                    my_thread.start()
                    juniper_Thedes.append(my_thread)
                for thread in juniper_Thedes:
                    thread.join()
            
            
        return Response(data={"timestamp":timestamp}, status=status.HTTP_200_OK)
    else:
        return Response(request.errors, status=status.HTTP_400_BAD_REQUEST)

        
@api_view(['GET', 'POST'])
def ciscoConfig_result(request):
    if request.method == 'GET':
        timestamp = request.GET.get('timestamp','')
        cisco = cisco_config_result.objects.filter(timestamp=timestamp)
        serializer = CiscoConfigOut_Serrializers(cisco, many=True)
        response = list(serializer.data)
        return Response(response)

    if request.method == 'POST':
        serializer = CiscoConfigOut_Serrializers(data=request.data)
        print(serializer)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Junpier:
    pass