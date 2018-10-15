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
"""
from __future__ import print_function
import argparse
from base64 import b64encode
from pprint import pprint
import urllib3
import requests


### Arguments parsing section ###
def cmd_args():
    """Handles command line arguments given."""
    parser = argparse.ArgumentParser(description='Put info here')
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

    parsed_arguments = parser.parse_args()

    # debug set print parser info
    if parsed_arguments.debug is True:
        print(parsed_arguments)


    # required args here
    if parsed_arguments.address is None:
        parser.error("-a target address is required, "
                     "use mgmt for local")

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
    post_data = '{"key":"value"}'
    post_result = requests.post(url, auth_token, post_data, headers=headers, verify=False)

    return post_result.json()


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



if __name__ == "__main__":

    # suppress ssl warning when disbling ssl verification with verify=False
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    OPT = cmd_args()

    # This is the auth token that will be used in request(5 min timeout)
    TOKEN = get_auth_token(OPT.address,
                           OPT.username,
                           OPT.password,
                           uri='/mgmt/shared/authn/login')


    if OPT.list_pools:
        REG_POOLS = ls_pools()
        for pool in REG_POOLS:
            print('{:38} {}'.format(pool['id'], pool['name']))
        print('\n')

    if OPT.pool_uuid:
        POOL_OFFERINGS = list_offereings(OPT.pool_uuid)
        #print(POOL_OFFERINGS[0].keys())
        #pprint(POOL_OFFERINGS['items'][0].keys())
        #pprint(POOL_OFFERINGS['items'][0]['licenseText'])
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
                print('{0:35}  {1:20} {2:10}'.format(offering['regKey'], offering['status'], offering.get('addOnKeys')))





