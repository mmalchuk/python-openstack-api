OS-API LIBRARY, CONFIGS AND USAGE EXAMPLE
=========================================

## Library Overview

* the library is created for testing purposes only
* it implements only v3 keystone authorization
* it implements only methods for creating test stand

## Usage Example

* the [example](create-test-stand.py) creates sample stand contains of:
    * the Cisco instance with three networks lan1, lan2, mgt
    * two of them (lan1 and lan2) are used for Linux boxes
    * the third one (mgt) is used for management (via Floating IP) and Internet (via Router)
* the Cisco instance is configured during the boot using the personality feature:
    * check the [config template](iosxe_config.txt) provided
    * for management the user 'cisco' with 'cisco123' password is created
    * the 'enable' password set to the same 'cisco123'
    * the SSH service enabled for management
* the Linux boxes created with Ubuntu Xenial Cloud images:
    * for initial configuration common [cloud-config](user-data.yaml) used
    * the SSH is allowed for management (connect from the Cisco instance)
    * user 'ubuntu' with 'ubuntu123' password created
    * for testing purposes sudo enabled for the 'ubuntu' user
