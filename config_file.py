import json
import subprocess

# Get the number of containers required by the tenant
numberOfContainers = int(raw_input("Please enter number of containers: "))

data = {}
data['tenant1'] = []

for i in range(numberOfContainers):
    # Take the IP subnet required by the tenant
    ipSubnet = str(raw_input("Please enter IP subnet: "))
    containerName = "C" + str(i + 1)
    # Put data in JSON file
    data['tenant1'].append({
        'name': containerName,
        'IP Subnet': ipSubnet
    })

# Dump config data in file in /etc
with open('/etc/configuration.json', 'w') as configfile:
    json.dump(data, configfile)


#command = "ip addr show ens3 | grep 'inet\b' | awk '{print $2}' | cut -d/ -f1"
#output = (str)(os.system(command))
#print(output.decode("utf-8"))

#output = subprocess.check_output(command)
#print(output.decode("utf-8"))
#p = subprocess.Popen(["sudo ansible-playbook -i inventory create_topology.yaml -v"], stdout=subprocess.PIPE)
#print(p1.communicate())

playbookOutput = subprocess.check_output('sudo ansible-playbook -i inventory create_topology.yaml -v', shell=True)
print(playbookOutput)
