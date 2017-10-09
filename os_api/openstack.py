import json
import requests


def die(res=None):
    """
    pretty print indented json and exit program
    :param res: json data
    :return: none
    """
    if hasattr(res, 'json'):
        print(json.dumps(res.json(), indent=2))
    elif type(res) == dict:
        print(json.dumps(res, indent=2))
    else:
        print(res)
    exit(1)


class OpenStackAPI:
    """
    OpenStack library for creating resources via HTTP API
    """

    # default mandatory headers for rest api requests
    headers = {'Content-Type': 'application/json; charset=utf-8'}

    def __init__(self, identity_url, name, password, domain, tenant):

        # OpenStack services endpoints
        self.endpoints = {}

        self._authenticate(identity_url, name, password, domain, tenant)

    def _authenticate(self, identity_url, name, password, domain, tenant):
        """
        authenticate, add token to the headers and populate endpoints
        """

        auth_data = {
            "auth": {
                "identity": {
                    "methods": [
                        "password"
                    ],
                    "password": {
                        "user": {
                            "domain": {
                                "name": domain,
                            },
                            "name": name,
                            "password": password,
                        }
                    }
                },
                "scope": {
                    "project": {
                        "domain": {
                            "name": domain,
                        },
                        "name": tenant,
                    }
                }
            }
        }

        print("")
        print("* Authenticate...".format(identity_url))

        response = None
        try:
            response = requests.post(identity_url, json=auth_data)
        except requests.exceptions.ConnectionError:
            die("! Connection Error ({})".format(identity_url))

        # update headers with token or die in case of error
        if response.ok and (response.status_code == requests.codes.created):
            self.headers['X-Auth-Token'] = response.headers['X-Subject-Token']
            print("- success.")
        else:
            die("! Authenticate Error ({}) : {}".format(identity_url, response.reason))

        # fill the endpoints dictionary from the auth response
        for service in response.json()['token']['catalog']:
            for endpoint in service['endpoints']:
                if endpoint['interface'] == 'public':
                    self.endpoints[service['type']] = endpoint['url']

    def network_create(self, name, admin_state_up=True):
        """
        create the network
        :param name: the name of the network
        :param admin_state_up: state of the network (optional)
        :return: network object
        """

        network = {
            "network": {
                "name": name,
                "admin_state_up": admin_state_up,
            }
        }

        print("")
        print("* Creating the network '{}'...".format(name))

        response = requests.post(self.endpoints['network'] + '/v2.0/networks', json=network, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.created):
            network = response.json()['network']
            print("- network ({}) created.".format(network['id']))
            return network
        else:
            die(response)

    def network_show(self, name):
        """
        get information about first network found by the name
        :param name: the name to looking for
        :return: network object
        """

        response = requests.get(self.endpoints['network'] + '/v2.0/networks?name={}'.format(name), headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            return response.json()['networks'][0]
        else:
            die(response)

    def subnet_create(self, network_id, name, cidr, enable_dhcp=False, gateway=None):
        """
        create subnet for the network
        :param network_id: the network id in which we create the subnet
        :param name: the name of the subnet we create
        :param cidr: the CIDR for the subnet
        :param enable_dhcp: create the DHCP server within the subnet (optional)
        :param gateway: default gateway in the subnet (optional)
        :return: subnet object
        """

        subnet = {
            "subnet": {
                "name": name,
                "enable_dhcp": enable_dhcp,
                "network_id": network_id,
                "gateway_ip": gateway,
                "ip_version": 4,
                "cidr": cidr,
            }
        }

        print("")
        print("* Creating the subnet '{}'...".format(name))

        response = requests.post(self.endpoints['network'] + '/v2.0/subnets', json=subnet, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.created):
            subnet = response.json()['subnet']
            print("- subnet ({}) created.".format(subnet['id']))
            return subnet
        else:
            die(response)

    def instance_launch(self, name, image_id, flavor_id, networks=None, ports=None,
                        config_drive=False, user_data=None, personality=None, metadata=None):
        """
        create and boot the server
        :param name: name of the server
        :param image_id: boot from the image
        :param flavor_id: use the flavor
        :param networks: networks to use
        :param ports: ports to use
        :param config_drive: use config drive (optional)
        :param user_data: user data (optional)
        :param personality: personality (optional)
        :param metadata: meta tags (optional)
        :return: server object
        """

        server = {
            "server": {
                "name": name,
                "imageRef": image_id,
                "flavorRef": flavor_id,
                "config_drive": config_drive,
            }
        }

        if networks:
            server['server']['networks'] = networks

        if ports:
            server['server']['networks'] = ports

        if personality:
            server['server']['personality'] = personality

        if user_data:
            server['server']['user_data'] = user_data

        if metadata:
            server['server']['metadata'] = metadata

        print("")
        print("* Launching the instance '{}'...".format(name))

        response = requests.post(self.endpoints['compute'] + '/servers', json=server, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.accepted):
            server = response.json()['server']
            print("- server ({}) created.".format(server['id']))
            return server
        else:
            die(response)

    def router_create(self, name, subnet_id, ext_network_id):
        """
        create router
        :param name: the name of the router
        :param subnet_id: create the router in the subnet
        :param ext_network_id: external network id for the gateway
        :return: router object
        """

        router = {
            "router": {
                "name": name,
                "admin_state_up": True,
            }
        }

        print("")
        print("* Creating the router '{}'...".format(name))

        response = requests.post(self.endpoints['network'] + '/v2.0/routers', json=router, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.created):
            router = response.json()['router']
            print("- router ({}) created.".format(router['id']))
        else:
            die(response)

        interface = {"subnet_id": subnet_id}

        response = requests.put(
            self.endpoints['network'] + '/v2.0/routers/{}/add_router_interface'.format(router['id']),
            json=interface, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            interface = response.json()
            print("- interface ({}) added to the router.".format(interface['id']))
        else:
            die(response)

        gateway_info = {"router": {"external_gateway_info": {"network_id": ext_network_id}}}

        response = requests.put(self.endpoints['network'] + '/v2.0/routers/{}'.format(router['id']),
                                json=gateway_info, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            router = response.json()['router']
            return router
        else:
            die(response)

    def port_create(self, network_id, subnet_id, fixed_ip, name=None, admin_state_up=True):
        """
        create the port on a network
        :param network_id: the id of the attached network
        :param subnet_id: subnet id from which the IP address is assigned
        :param fixed_ip: the IP address for the port
        :param name: the name of the port (optional)
        :param admin_state_up: state of the port (optional)
        :return: port object
        """

        port = {
            "port": {
                "network_id": network_id,
                "fixed_ips": [
                    {
                        "subnet_id": subnet_id,
                        "ip_address": fixed_ip
                    }
                ],
                "admin_state_up": admin_state_up
            }
        }

        if name:
            port["port"]["name"] = name

        print("")
        print("* Creating the port in subnet ({}) with ip '{}'...".format(subnet_id, fixed_ip))

        response = requests.post(self.endpoints['network'] + '/v2.0/ports', json=port, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.created):
            port = response.json()['port']
            print("- port ({}) created.".format(port['id']))
            return port
        else:
            die(response)

    def port_delete(self, port_id):
        """
        deleting the port by id
        :param port_id: the id os the port
        :return: None
        """

        response = requests.delete(self.endpoints['network']+'/v2.0/ports/{}'.format(port_id), headers=self.headers)

        if response.ok and (response.status_code == requests.codes.no_content):
            print("- port ({}) deleted.".format(port_id))
        else:
            die(response)

    def floatingip_create(self, floating_network_id, port_id):
        """
        create floating ip and associate to the port
        :param floating_network_id: the id of the network associated with the floating IP
        :param port_id: the id of the internal port be associated with the floating IP
        :return: floatingip object
        """

        print("")
        print("* Creating the floating ip for the port '{}'...".format(port_id))

        floatingip = {
            "floatingip": {
                "floating_network_id": floating_network_id,
                "port_id": port_id
            }
        }

        response = requests.post(self.endpoints['network'] + '/v2.0/floatingips', json=floatingip, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.created):
            floatingip = response.json()['floatingip']
            print("- created {}".format(floatingip['floating_ip_address']))
            return floatingip
        else:
            die(response)

    def cleanup_resources(self, prefix):
        """
        remove resources which names started by the prefix
        :param prefix: prefix for the names
        :return:
        """

        print("")
        print("* Cleanup resources...")

        # remove routers, their interfaces, gateways and floating ips
        response = requests.get(self.endpoints['network'] + '/v2.0/routers?limit=10000', headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            for router in response.json()['routers']:
                if router['name'].startswith(prefix):

                    # find floating ips related to the router
                    response = requests.get(
                        self.endpoints['network'] + '/v2.0/floatingips?router_id={}'.format(router['id']),
                        headers=self.headers)

                    if response.ok and (response.status_code == requests.codes.ok):
                        for floatingip in response.json()['floatingips']:

                            response = requests.delete(
                                self.endpoints['network'] + '/v2.0/floatingips/{}'.format(floatingip['id']),
                                headers=self.headers)

                            if response.ok and (response.status_code == requests.codes.no_content):
                                print("- floating ip '{}' deleted.".format(floatingip['floating_ip_address']))
                            else:
                                die(response)
                    else:
                        die(response)

                    # clear router gateway
                    if router['external_gateway_info']:

                        gateway_info = {"router": {"external_gateway_info": {}}}

                        response = requests.put(self.endpoints['network'] + '/v2.0/routers/{}'.format(router['id']),
                                                json=gateway_info, headers=self.headers)

                        if response.ok and (response.status_code == requests.codes.ok):
                            print("- gateway from the router '{}' removed.".format(router['name']))
                        else:
                            die(response)

                    # list ports and delete found interfaces
                    response = requests.get(self.endpoints['network'] + '/v2.0/ports?device_id={}'.format(router['id']),
                                            headers=self.headers)

                    if response.ok and (response.status_code == requests.codes.ok):
                        for port in response.json()['ports']:

                            interface = {"port_id": port['id']}

                            response = requests.put(
                                self.endpoints['network'] + '/v2.0/routers/{}/remove_router_interface'.format(
                                    router['id']), json=interface, headers=self.headers)

                            if response.ok and (response.status_code == requests.codes.ok):
                                interface = response.json()
                                print(
                                    "- port ({}) from the router '{}' removed.".format(interface['port_id'],
                                                                                       router['name']))
                            else:
                                die(response)
                    else:
                        die(response)

                    # delete the router itself
                    response = requests.delete(self.endpoints['network'] + '/v2.0/routers/{}'.format(router['id']),
                                               headers=self.headers)

                    if response.ok and (response.status_code == requests.codes.no_content):
                        print("- router '{}' ({}) deleted.".format(router['name'], router['id']))
                    else:
                        die(response)
        else:
            die(response)

        # remove instances
        response = requests.get(self.endpoints['compute'] + '/servers?limit=10000', headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            for server in response.json()['servers']:
                if server['name'].startswith(prefix):

                    response = requests.delete(self.endpoints['compute'] + '/servers/{}'.format(server['id']),
                                               headers=self.headers)

                    if response.ok and (response.status_code == requests.codes.no_content):
                        print("- server: '{}' ({}) terminated.".format(server['name'], server['id']))
                    else:
                        die(response)
        else:
            die(response)

        # remove networks, their subnets and ports
        response = requests.get(self.endpoints['network'] + '/v2.0/networks?limit=10000', headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            for network in response.json()['networks']:
                if network['name'].startswith(prefix):

                    response = requests.get(
                        self.endpoints['network'] + '/v2.0/ports?network_id={}'.format(network['id']),
                        headers=self.headers)

                    if response.ok and (response.status_code == requests.codes.ok):
                        for port in response.json()['ports']:

                            response = requests.delete(self.endpoints['network'] + '/v2.0/ports/{}'.format(port['id']),
                                                       headers=self.headers)

                            if response.ok and (response.status_code == requests.codes.no_content):
                                print("- port ({}) deleted.".format(port['id']))
                            else:
                                die(response)
                    else:
                        die(response)

                    response = requests.delete(self.endpoints['network'] + '/v2.0/networks/{}'.format(network['id']),
                                               headers=self.headers)

                    if response.ok and (response.status_code == requests.codes.no_content):
                        print("- network '{}' ({}) deleted.".format(network['name'], network['id']))
                    else:
                        die(response)
        else:
            die(response)
