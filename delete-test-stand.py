#!/usr/bin/env python

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
