#!/usr/bin/env python

import base64
import os
import os_api

try:
    os_auth_url = os.environ['OS_AUTH_URL'] + '/auth/tokens'
    os_username = os.environ['OS_USERNAME']
    os_password = os.environ['OS_PASSWORD']
    os_project_name = os.environ['OS_PROJECT_NAME']
    os_user_domain_name = os.environ['OS_USER_DOMAIN_NAME']
except KeyError:
    print("Error! Please export OpenStack v3 environment variables first!")
    exit(1)

# authorize and setup endpoints
test_os = os_api.OpenStackAPI(os_auth_url, os_username, os_password,
                              os_user_domain_name, os_project_name)

# cleanup previous test stand
test_os.cleanup_resources('test_')

# resource names and addresses
ext_net_name = "ext-net"
#
test_lan1_name = "test_lan1"
test_lan2_name = "test_lan2"
test_mgt0_name = "test_mgt0"
#
test_cisco_name = "test_cisco"
test_linux1_name = "test_linux1"
test_linux2_name = "test_linux2"
test_router_name = "test_router"
#
test_lan1_cidr = "192.168.1.0/30"
test_lan1_mask = "255.255.255.252"
test_lan1cisco_ip = "192.168.1.2"
test_lan1linux_ip = "192.168.1.1"
#
test_lan2_cidr = "192.168.1.4/30"
test_lan2_mask = "255.255.255.252"
test_lan2cisco_ip = "192.168.1.5"
test_lan2linux_ip = "192.168.1.6"
#
test_mgt0_cidr = "192.168.2.0/24"
test_mgt0_mask = "255.255.255.0"
test_mgt0cisco_ip = "192.168.2.20"
test_mgt0cisco_gw = "192.168.2.254"

# create networks
test_lan1_id = test_os.network_create(test_lan1_name)['id']
test_lan2_id = test_os.network_create(test_lan2_name)['id']
test_mgt0_id = test_os.network_create(test_mgt0_name)['id']

# create subnets
test_lan1subnet_id = test_os.subnet_create(test_lan1_id,
                                           test_lan1_name + 'subnet',
                                           test_lan1_cidr,
                                           gateway=test_lan1cisco_ip)['id']
test_lan2subnet_id = test_os.subnet_create(test_lan2_id,
                                           test_lan2_name + 'subnet',
                                           test_lan2_cidr,
                                           gateway=test_lan2cisco_ip)['id']
test_mgt0subnet_id = test_os.subnet_create(test_mgt0_id,
                                           test_mgt0_name + 'subnet',
                                           test_mgt0_cidr,
                                           gateway=test_mgt0cisco_gw)['id']

# create ports for the cisco instance
test_lan1cisco_id = test_os.port_create(test_lan1_id,
                                        test_lan1subnet_id,
                                        test_lan1cisco_ip)['id']
test_lan2cisco_id = test_os.port_create(test_lan2_id,
                                        test_lan2subnet_id,
                                        test_lan2cisco_ip)['id']
test_mgt0cisco_id = test_os.port_create(test_mgt0_id,
                                        test_mgt0subnet_id,
                                        test_mgt0cisco_ip)['id']

# create ports for the linuxes
test_lan1linux1_id = test_os.port_create(test_lan1_id,
                                         test_lan1subnet_id,
                                         test_lan1linux_ip)['id']
test_lan2linux2_id = test_os.port_create(test_lan2_id,
                                         test_lan2subnet_id,
                                         test_lan2linux_ip)['id']

# get the external (provider) network id
ext_net_id = test_os.network_show(ext_net_name)['id']

# create the router for the external network access
test_os.router_create(test_router_name, test_mgt0subnet_id, ext_net_id)
# create the floating ip for the management port
test_os.floatingip_create(ext_net_id, test_mgt0cisco_id)

# prepare cisco configuration
with open('iosxe_config.txt') as f:
    iosxe_config_data = f.read().format(
        test_cisco_name=test_cisco_name,
        test_lan1_name=test_lan1_name,
        test_lan1cisco_ip=test_lan1cisco_ip,
        test_lan1_mask=test_lan1_mask,
        test_lan2_name=test_lan2_name,
        test_lan2cisco_ip=test_lan2cisco_ip,
        test_lan2_mask=test_lan2_mask,
        test_mgt0_name=test_mgt0_name,
        test_mgt0cisco_ip=test_mgt0cisco_ip,
        test_mgt0_mask=test_mgt0_mask,
        test_mgt0cisco_gw=test_mgt0cisco_gw
    )
iosxe_config_encoded = base64.standard_b64encode(iosxe_config_data)

# create the personality object for the cisco instance
test_cisco_personality = [{
    "path": "iosxe_config.txt",
    "contents": iosxe_config_encoded
}]

# create the ports object for the cisco instance
test_cisco_ports = [
    {"port": test_lan1cisco_id},
    {"port": test_lan2cisco_id},
    {"port": test_mgt0cisco_id}
]

# launch the cisco instance
test_os.instance_launch(test_cisco_name,
                        "4468f4a2-96ac-4e1b-9a76-b3f185e4590d",
                        "6",
                        ports=test_cisco_ports,
                        config_drive=True,
                        personality=test_cisco_personality)

# prepare linuxes user data
with open('user-data.yaml') as f:
    test_linux_user_data = base64.standard_b64encode(f.read())

# create the ports object for the linux instance
test_linux1_ports = [{"port": test_lan1linux1_id}]

# launch the linux instance
test_os.instance_launch(test_linux1_name,
                        "96be672c-a1a2-46c0-a73f-4cd6a179186f",
                        "2",
                        networks=test_linux1_ports,
                        config_drive=True,
                        user_data=test_linux_user_data)

# create the ports object for the linux instance
test_linux2_ports = [{"port": test_lan2linux2_id}]

# launch the linux instance
test_os.instance_launch(test_linux2_name,
                        "96be672c-a1a2-46c0-a73f-4cd6a179186f",
                        "2",
                        networks=test_linux2_ports,
                        config_drive=True,
                        user_data=test_linux_user_data)
