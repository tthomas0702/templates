#!/usr/bin/env python


"""
File name: reg_pool_tool.py
Author: Tim Thomas
Date created: 10/12/2018
Date last modified: 10/12/2018
Python Version: 2.7.15
version:
    0.0.1 incomplete
Example:


Copyright 2018 Tim Thomas

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.



"""

from __future__ import print_function
import argparse
from base64 import b64encode
import json
from pprint import pprint
import sys
import time
import urllib3
import requests


### Arguments parsing section ###
def cmd_args():
    """Handles command line arguments given."""
    parser = argparse.ArgumentParser(description='This is a tool for working'
                                                 'with regkey pool on BIG-IQ')
    parser.add_argument('-d',
                        '--debug',
                        action="store_true",
                        default=False,
                        help='enable debug')
    parser.add_argument('-v',
                        '--verbose',
                        action="store_true",
                        default=False,
                        help='enable verbose for options that have it')
    parser.add_argument('-a',
                        '--address',
                        action="store",
                        dest="address",
                        help='IP address of the target host')
    parser.add_argument('-u',
                        '--username',
                        action="store",
                        dest="username",
                        default='admin',
                        help='username for auth to host')
    parser.add_argument('-p',
                        '--password',
                        action="store",
                        dest="password",
                        default='admin',
                        help='password for auth to host')
    parser.add_argument('-l',
                        '--list-pools',
                        action="store_true",
                        default=False,
                        help='list the UUIDs for existing regkey pools, requires no args')
    parser.add_argument('-o',
                        '--offerings',
                        action="store",
                        dest="pool_uuid",
                        help='take UUID of pool as arg and list the offerings for a pool'
                             ' use -v to also show the active modules')
    parser.add_argument('-r',
                        '--regkey',
                        action="store",
                        dest="reg_key",
                        help='takes and stores the regkey for use in other options')
    parser.add_argument('-A',
                        '--add-on-keys',
                        action="store",
                        dest="add_on_key_list",
                        help='takes list of addon keys for use by other options')
    parser.add_argument('-i',
                        '--install-offering',
                        action="store",
                        dest="install_pool_uuid",
                        help='takes pool UUID as arg and installs new offering,'
                             'requires -r, -A can be used to install addon keys at'
                             'the same time')
    parser.add_argument('-m',
                        '--modify-offering-addons',
                        action="store",
                        dest="modify_pool_uuid",
                        help='takes pool UUID as arg and installs addon to offering,'
                             'requires -A [addon_key_list] and -r reg_key')


    parsed_arguments = parser.parse_args()

    # debug set print parser info
    if parsed_arguments.debug is True:
        print(parsed_arguments)


    # required args here
    if parsed_arguments.address is None:
        parser.error('-a target address is required, '
                     'use mgmt for local')
    if parsed_arguments.install_pool_uuid:
        if parsed_arguments.reg_key is None:
            parser.error('-i requires -r')
    if parsed_arguments.modify_pool_uuid:
        if parsed_arguments.add_on_key_list is None:
            parser.error('-m requires -A and -r')
        elif parsed_arguments.reg_key is None:
            parser.error('-m requires -A and -r')

    return parsed_arguments

### END ARGPARSE SECTION ###


def to_unicode(unicode_or_str):
    """This function is used to make sure that they instance you are working with
    is unicode, this version of the function is for python 2.x"""
    if isinstance(unicode_or_str, str):
        value = unicode_or_str.decode('utf-8')
    else:
        value = unicode_or_str
    return value  # Instance of unicode


def to_str(unicode_or_str):
    """This function is used to make sure that they instance you are working with
    is a str, this version of the function is for python 2.x"""
    if isinstance(unicode_or_str, unicode):
        value = unicode_or_str.encode('utf-8')
    else:
        value = unicode_or_str
    return value  # Instance of str


def get_auth_token(address, user, password,
                   uri='/mgmt/shared/authn/login'):  # -> unicode
    """Get and auth token( to be used but other requests"""
    credentials_list = [user, ":", password]
    credentials = ''.join(credentials_list)
    user_and_pass = b64encode(credentials).decode("ascii")
    headers = {'Authorization':'Basic {}'.format(user_and_pass), 'Content-Type':'application/json'}
    post_data = '{"username":"' + user + '","password":"' + password +'"}'
    url_list = ['https://', address, uri]
    url = ''.join(url_list)
    request_result = requests.post(url, headers=headers, data=post_data, verify=False)

    #returns an instance of unicode that is an auth token with 300 dec timeout
    return request_result.json()['token']['token']


def get(url, auth_token, debug=False, return_encoding='json'):
    """Generic GET function. The return_encoding can be:'text', 'json', 'content'(binary),
    or raw """
    headers = {'X-F5-Auth-Token':'{}'.format(auth_token), 'Content-Type':'application/json'}

    get_result = requests.get(url, headers=headers, verify=False)

    if debug is True:
        print('get_result.encoding: {}'.format(get_result.encoding))
        print('get_result.status_code: {}'.format(get_result.status_code))
        print('get_result.raise_for_status: {}'.format(
            get_result.raise_for_status()))

    if return_encoding == 'json':
        return get_result.json()
    elif return_encoding == 'text':
        return get_result.text
    elif return_encoding == 'content':
        return get_result.content
    elif return_encoding == 'raw':
        return get_result.raw()  # requires 'stream=True' in request


def post(url, auth_token, post_data):
    """ generic POST function """
    headers = {'X-F5-Auth-Token':'{}'.format(auth_token), 'Content-Type':'application/json'}
    #post_data = '{"key":"value"}'
    post_result = requests.post(url, post_data, headers=headers, verify=False)
    if OPT.debug is True:
        print('post_result.encoding: {}'.format(post_result.encoding))
        print('post_result.status_code: {}'.format(post_result.status_code))
        print('post_result.raise_for_status: {}'.format(
            post_result.raise_for_status()))

    return post_result.json()

def patch(url, auth_token, patch_data):
    """ generic PATCH function """
    headers = {'X-F5-Auth-Token':'{}'.format(auth_token), 'Content-Type':'application/json'}
    #patch_data = '{"key":"value"}'
    patch_result = requests.patch(url, patch_data, headers=headers, verify=False)

    return patch_result.json()


def ls_pools():
    """ Lists existing regkey pools """
    uri = '/mgmt/cm/device/licensing/pool/regkey/licenses'
    url_list = ['https://', OPT.address, uri]
    url = ''.join(url_list)
    pool_list_result = get(url, TOKEN, debug=False, return_encoding='json')

    return pool_list_result['items']


def list_offereings(regkey_pool_uuid):
    """Returns a list of offerings for the regkey pool UUID given"""
    url_list = ['https://', OPT.address, '/mgmt/cm/device/licensing/pool/regkey/licenses/',
                regkey_pool_uuid, '/offerings']
    url = ''.join(url_list)
    offering_get_result = get(url, TOKEN, OPT.debug, return_encoding='json')
    offering_list_result = offering_get_result['items']

    return offering_list_result




def install_offering(regkey_pool_uuid, new_regkey, add_on_keys):
    """
    :type regkey_pool_uuid: str
    :type new_regkey: str
    :type add_on_keys: List[str]
    """
    uri = '/mgmt/cm/device/licensing/pool/regkey/licenses/'
    url_list = ['https://', OPT.address, uri, OPT.install_pool_uuid, '/offerings/']
    url = ''.join(url_list)

    if OPT.add_on_key_list:
        post_dict = {"regKey": OPT.reg_key, "status": "ACTIVATING_AUTOMATIC", "addOnKeys": OPT.add_on_key_list.split(','), "description" : ""}
    else:
        post_dict = {"regKey": OPT.reg_key, "status": "ACTIVATING_AUTOMATIC", "description" : ""}
    payload = json.dumps(post_dict)
    try:
        print(payload)
        post_result = post(url, TOKEN, payload)
        print('\nSent base regkey {} to License server\nstatus:'.format(OPT.reg_key))
        print(type(post_result))
    except:
        print('Post to License server failed')
        raise

    # poll for "eulaText"
    poll_result = {}
    attempt = 0 # keep track of tries and give up exit script after 10
    uri = '/mgmt/cm/device/licensing/pool/regkey/licenses/'
    url_list = ['https://', OPT.address, uri, OPT.install_pool_uuid, '/offerings/', OPT.reg_key]
    url = ''.join(url_list)
    while "eulaText" not in poll_result.keys():
        try:
            poll_result = get(url, TOKEN, OPT.debug, return_encoding='json')
            print('\npoll {} for {}'.format(attempt +1, OPT.reg_key))
            if "fail" in poll_result['message']:
                sys.exit(poll_result['message'])
            print(poll_result['status'])
            print(poll_result['message'])
            time.sleep(5)
        except:
            print('Poll for eula failed for regkey {}'.format(OPT.reg_key))
            raise
        attempt += 1
        if attempt == 5:
            sys.exit('Giving up after 5 tries to poll for EULA for RegKey')
    print('Finished polling...')

    # since we have eula back we need to patch back the eula
    # update "status" in dict
    poll_result["status"] = "ACTIVATING_AUTOMATIC_EULA_ACCEPTED"
    uri = '/mgmt/cm/device/licensing/pool/regkey/licenses/'
    url_list = ['https://', OPT.address, uri, OPT.install_pool_uuid, '/offerings/', OPT.reg_key]
    url = ''.join(url_list)
    patch_dict = {"status":poll_result['status'], "eulaText": poll_result['eulaText']}
    patch_payload = json.dumps(patch_dict)
    print('sending PATCH to accept EULA for {}'.format(OPT.reg_key))
    try:
        patch_result = patch(url, TOKEN, patch_payload)
        print('{} for {}'.format(patch_result['message'], OPT.reg_key))
        print(patch_result["status"])
    except:
        raise


if __name__ == "__main__":

    # suppress ssl warning when disbling ssl verification with verify=False
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    OPT = cmd_args()

    # This is the auth token that will be used in request(5 min timeout)
    TOKEN = get_auth_token(OPT.address,
                           OPT.username,
                           OPT.password,
                           uri='/mgmt/shared/authn/login')

    # -l
    if OPT.list_pools:
        REG_POOLS = ls_pools()
        for pool in REG_POOLS:
            print('{:38} {}'.format(pool['id'], pool['name']))
        print('\n')

    # -o
    if OPT.pool_uuid:
        POOL_OFFERINGS = list_offereings(OPT.pool_uuid)
        print('{0:35}  {1:20} {2:10}'.format('RegKey', 'Status', 'addOnKeys'))
        print(73 * '-')
        for offering in  POOL_OFFERINGS:
            if 'addOnKeys' in offering:
                print('{0:35}  {1:20} {2:10}'.format(offering['regKey'], offering['status'], 'YES'))
                # if verbose given list Active modules
                if OPT.verbose:
                    active_modules = offering['licenseText'].splitlines()
                    for line in active_modules:
                        if line.startswith('active module'):
                            print('   {} '.format(line[:80]))
            else:
                print('{0:35}  {1:20} {2:10}'.format(offering['regKey'],
                                                     offering['status'],
                                                     offering.get('addOnKeys')))


    # -i install new offereing with or without an addon keys
    if OPT.install_pool_uuid:
        install_offering(OPT.install_pool_uuid, OPT.reg_key, OPT.add_on_key_list)

    
    print('END')



# TODO install_offering is working, need to clean up and then add install to exsiting offering





