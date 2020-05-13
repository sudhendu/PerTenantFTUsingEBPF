import json
import subprocess
import socket
import struct
import ipaddress
import binascii

#command = "ip addr show ens3 | grep 'inet\b' | awk '{print $2}' | cut -d/ -f1"
#output = (str)(os.system(command))
#print(output.decode("utf-8"))

#output = subprocess.check_output(command)
#print(output.decode("utf-8"))
data = {}
data['tenant1'] = []

# For our VM topology
vethNS1_1IP = subprocess.check_output("sudo ip netns exec ns1-1 ip addr show veth-ns1-1 | grep 'inet\\b' | awk '{print $2}' | cut -d/ -f1", shell=True)
vethNS1_2IP = subprocess.check_output("sudo ip netns exec ns1-2 ip addr show veth-ns1-2 | grep 'inet\\b' | awk '{print $2}' | cut -d/ -f1", shell=True)
vethNS1_1MAC = subprocess.check_output("sudo ip netns exec ns1-1 cat /sys/class/net/veth-ns1-1/address", shell=True)
vethNS1_2MAC = subprocess.check_output("sudo ip netns exec ns1-2 cat /sys/class/net/veth-ns1-2/address", shell=True)

# For container topology
vethC1IP = subprocess.check_output("sudo docker exec C1 ip addr show veth-C1-br40 | grep 'inet\\b' | awk '{print $2}' | cut -d/ -f1", shell=True)
vethC2IP = subprocess.check_output("sudo docker exec C2 ip addr show veth-C2-br140 | grep 'inet\\b' | awk '{print $2}' | cut -d/ -f1", shell=True)
vethC1MAC = subprocess.check_output("sudo docker exec C1 cat /sys/class/net/veth-C1-br40/address", shell=True)
vethC2MAC = subprocess.check_output("sudo docker exec C2 cat /sys/class/net/veth-C2-br140/address", shell=True)


# For VM topology

data['tenant1'].append({
    'name': "C1",
    'IP Address': vethNS1_1IP,
    'MAC Address': vethNS1_1MAC
})
data['tenant1'].append({
    'name': "C2",
    'IP Address': vethNS1_2IP,
    'MAC Address': vethNS1_2MAC
})

# For container topology
data['tenant1'].append({
    'name': "Container1",
    'IP Address': vethC1IP,
    'MAC Address': vethC1MAC,
    'Device ID': "veth-br40-C1"
})
data['tenant1'].append({
    'name': "Container2",
    'IP Address': vethC2IP,
    'MAC Address': vethC2MAC,
    'Device ID': "veth-br140-C2"
})

# Dump config data in file in /var
with open('/var/runtimeConfiguration.json', 'w') as configfile:
    json.dump(data, configfile)

with open('/var/runtimeConfiguration.json') as json_file:
    data = json.load(json_file)
    for p in data['tenant1']:
        ipAddress = p['IP Address']
        ipAddress = ipAddress[:-1]
        macAddress = p['MAC Address']
        macAddress = macAddress[:-1]
        deviceId = p['Device ID']
        #macBytes = macAddress.replace(':', '').decode('hex')
        #print(macBytes[0:6])
        print(ipAddress)
        print(macAddress)
        if ipAddress == "10.0.40.2":
            subprocess.call("sudo /home/ece792/prototype-kernel/kernel/samples/bpf/bpf_map_create "+deviceId+" tenant1 "+ipAddress+" "+macAddress, shell=True)
        else:
            subprocess.call("sudo /home/ece792/prototype-kernel/kernel/samples/bpf/bpf_map_create "+deviceId+" tenant1 "+ipAddress+" "+macAddress, shell=True)
        #ipAddressDecimal = struct.unpack('>L',socket.inet_aton(ipAddressReversed))[0]
        #print(ipAddressDecimal)
        #print('Name: ' + p['name'])
        #print('IP Address: ' + p['IP Address'])
        #print('MAC Address: ' + p['MAC Address'])
        #print('')
