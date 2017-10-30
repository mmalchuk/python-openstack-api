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
            die("! Authenticate Error ({}) : {}"
                .format(identity_url, response.reason))

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

        response = requests.post(
            self.endpoints['network'] + '/v2.0/networks',
            json=network, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.created):
            network = response.json()['network']
            print("- network ({}) created.".format(network['id']))
            return network
        else:
            die(response)

    def network_list(self, list_limit=10000):
        """
        get list of the networks
        :param list_limit: return maximum number of the networks
        :return: list of the network objects
        """

        response = requests.get(
            self.endpoints['network'] + '/v2.0/networks?limit={}'
            .format(list_limit),
            headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            networks = response.json()['networks']
            return networks
        else:
            die(response)

    def network_delete(self, network_id):
        """
        delete network
        :param network_id: network id
        :return: None
        """
        response = requests.delete(
            self.endpoints['network'] + '/v2.0/networks/{}'.format(network_id),
            headers=self.headers)

        if response.ok and (response.status_code == requests.codes.no_content):
            print("- network '{}' deleted.".format(network_id))
        else:
            die(response)

    def network_show(self, name):
        """
        get information about first network found by the name
        :param name: the name to looking for
        :return: network object
        """

        response = requests.get(
            self.endpoints['network'] + '/v2.0/networks?name={}'.format(name),
            headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            return response.json()['networks'][0]
        else:
            die(response)

    def subnet_create(self, network_id, name, cidr,
                      enable_dhcp=False, gateway=None):
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

        response = requests.post(
            self.endpoints['network'] + '/v2.0/subnets',
            json=subnet, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.created):
            subnet = response.json()['subnet']
            print("- subnet ({}) created.".format(subnet['id']))
            return subnet
        else:
            die(response)

    def server_create(self, name, image_id, flavor_id,
                      networks=None, ports=None, config_drive=False,
                      user_data=None, personality=None, metadata=None):
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
        print("* Launching the server '{}'...".format(name))

        response = requests.post(
            self.endpoints['compute'] + '/servers',
            json=server, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.accepted):
            server = response.json()['server']
            print("- server ({}) created.".format(server['id']))
            return server
        else:
            die(response)

    def server_list(self, list_limit=10000):
        """
        get list of the servers
        :param list_limit: return maximum number of the servers
        :return: list of the server objects
        """

        response = requests.get(
            self.endpoints['compute'] + '/servers?limit={}'.format(list_limit),
            headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            servers = response.json()['servers']
            return servers
        else:
            die(response)

    def server_delete(self, server_id):
        """
        terminate the server
        :param server_id: server id
        :return: None
        """

        response = requests.delete(
            self.endpoints['compute'] + '/servers/{}'.format(server_id),
            headers=self.headers)

        if response.ok and (response.status_code == requests.codes.no_content):
            print("- server: '{}' terminated.".format(server_id))
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

        response = requests.post(
            self.endpoints['network'] + '/v2.0/routers',
            json=router, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.created):
            router = response.json()['router']
            print("- router ({}) created.".format(router['id']))
        else:
            die(response)

        interface = {"subnet_id": subnet_id}

        response = requests.put(
            self.endpoints['network'] + '/v2.0/routers/{}/add_router_interface'
            .format(router['id']),
            json=interface, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            interface = response.json()
            print("- interface ({}) added to the router."
                  .format(interface['id']))
        else:
            die(response)

        gateway_info = {
            "router": {
                "external_gateway_info": {
                    "network_id": ext_network_id
                }
            }
        }

        response = requests.put(
            self.endpoints['network'] + '/v2.0/routers/{}'
            .format(router['id']),
            json=gateway_info, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            router = response.json()['router']
            return router
        else:
            die(response)

    def router_list(self, list_limit=10000):
        """
        get list of the routers
        :param list_limit: return maximum number of the routers
        :return: list of the router objects
        """
        response = requests.get(
            self.endpoints['network'] + '/v2.0/routers?limit={}'
            .format(list_limit),
            headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            routers = response.json()['routers']
            return routers
        else:
            die(response)

    def router_clear_gateway(self, router_id):
        """
        clear gateway for the router
        :param router_id: the router id
        :return: None
        """

        gateway_info = {
            "router": {
                "external_gateway_info": {}
            }
        }

        response = requests.put(
            self.endpoints['network'] + '/v2.0/routers/{}'.format(router_id),
            json=gateway_info, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            print("- gateway from the router '{}' removed.".format(router_id))
        else:
            die(response)

    def router_delete_interface(self, port_id, router_id):
        """
        delete interface from the router
        :param port_id:
        :param router_id:
        :return:
        """

        interface = {"port_id": port_id}

        response = requests.put(
            self.endpoints['network'] +
            '/v2.0/routers/{}/remove_router_interface'.format(router_id),
            json=interface, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            print("- port ({}) from the router '{}' removed."
                  .format(port_id, router_id))
        else:
            die(response)

    def router_delete(self, router_id):
        """
        delete router
        :param router_id: router id
        :return: None
        """

        response = requests.delete(
            self.endpoints['network'] + '/v2.0/routers/{}'.format(router_id),
            headers=self.headers)

        if response.ok and (response.status_code == requests.codes.no_content):
            print("- router '{}' deleted.".format(router_id))
        else:
            die(response)

    def port_create(self, network_id, subnet_id, fixed_ip, name=None,
                    admin_state_up=True, port_security_enabled=False):
        """
        create the port on a network
        :param network_id: the id of the attached network
        :param subnet_id: subnet id from which the IP address is assigned
        :param fixed_ip: the IP address for the port
        :param name: the name of the port (optional)
        :param admin_state_up: state of the port (optional)
        :param port_security_enabled: anti-spoofing (optional)
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
                "admin_state_up": admin_state_up,
                "port_security_enabled": port_security_enabled
            }
        }

        if name:
            port["port"]["name"] = name

        print("")
        print("* Creating the port in subnet ({}) with ip '{}'..."
              .format(subnet_id, fixed_ip))

        response = requests.post(
            self.endpoints['network'] + '/v2.0/ports',
            json=port, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.created):
            port = response.json()['port']
            print("- port ({}) created.".format(port['id']))
            return port
        else:
            die(response)

    def port_list(self, list_filter):
        """
        list ports
        :param list_filter: key-value to filter list
        :return: list of the port objects
        """

        if list_filter:
            list_filter = '?' + list_filter

        response = requests.get(
            self.endpoints['network'] + '/v2.0/ports{}'.format(list_filter),
            headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            ports = response.json()['ports']
            return ports
        else:
            die(response)

    def port_delete(self, port_id):
        """
        deleting the port by id
        :param port_id: the id os the port
        :return: None
        """

        response = requests.delete(
            self.endpoints['network'] + '/v2.0/ports/{}'.format(port_id),
            headers=self.headers)

        if response.ok and (response.status_code == requests.codes.no_content):
            print("- port ({}) deleted.".format(port_id))
        else:
            die(response)

    def floatingip_create(self, floating_network_id, port_id):
        """
        create floating ip and associate to the port
        :param floating_network_id: the id of the network associated with
               the floating IP
        :param port_id: the id of the internal port be associated with
               the floating IP
        :return: floatingip object
        """

        print("")
        print("* Creating the floating ip for the port '{}'..."
              .format(port_id))

        floatingip = {
            "floatingip": {
                "floating_network_id": floating_network_id,
                "port_id": port_id
            }
        }

        response = requests.post(
            self.endpoints['network'] + '/v2.0/floatingips',
            json=floatingip, headers=self.headers)

        if response.ok and (response.status_code == requests.codes.created):
            floatingip = response.json()['floatingip']
            print("- created {}".format(floatingip['floating_ip_address']))
            return floatingip
        else:
            die(response)

    def floatingip_list(self, list_filter=""):
        """
        list floating IPs
        :param list_filter: key-value to filter list
        :return: list of the floatingip objects
        """

        if list_filter:
            list_filter = '?' + list_filter

        response = requests.get(
            self.endpoints['network'] + '/v2.0/floatingips{}'
            .format(list_filter),
            headers=self.headers)

        if response.ok and (response.status_code == requests.codes.ok):
            floatingips = response.json()['floatingips']
            return floatingips
        else:
            die(response)

    def floatingip_delete(self, floatingip_id):
        """
        delete floating IP
        :param floatingip_id:
        :return: None
        """

        response = requests.delete(
            self.endpoints['network'] + '/v2.0/floatingips/{}'
            .format(floatingip_id),
            headers=self.headers)

        if response.ok and (response.status_code == requests.codes.no_content):
            print("- floating ip '{}' deleted.".format(floatingip_id))
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
        routers = self.router_list()
        for router in routers:
            if router['name'].startswith(prefix):

                # find floating ips related to the router
                floatingips = self.floatingip_list('router_id={}'
                                                   .format(router['id']))
                for floatingip in floatingips:
                    self.floatingip_delete(floatingip['id'])

                # clear router gateway
                if router['external_gateway_info']:
                    self.router_clear_gateway(router['id'])

                # list ports and delete found interfaces
                ports = self.port_list('device_id={}'.format(router['id']))
                for port in ports:
                    self.router_delete_interface(port['id'], router['id'])

                # delete the router itself
                self.router_delete(router['id'])

        # remove servers
        servers = self.server_list()
        for server in servers:
            if server['name'].startswith(prefix):
                # delete the server
                self.server_delete(server['id'])

        # remove networks, their subnets and ports
        networks = self.network_list()
        for network in networks:
            if network['name'].startswith(prefix):

                # list all ports on the network and delete them
                ports = self.port_list('network_id={}'.format(network['id']))
                for port in ports:
                    self.port_delete(port['id'])

                # delete the network itself
                self.network_delete(network['id'])
