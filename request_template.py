#!/usr/bin/env python

"""This is a Python 2.x template for may http calls. This is mostly geared toward
making rest calls to F5 devices"""

import argparse
import requests


def parse_args():
    parser = argparse.ArgumentParser(description='Put info here')
    parser.add_argument('-d',
                        '--debug',
                        action="store_true",
                        default=False,
                        help='enable debug')
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

    opts = parser.parse_args()

    if opts.debug is True:
        print opts

    if opts.address is None:
        parser.error("-a target BIG-IQ address is required, "
                     "use 127.0.0.1 for local")
    return opts


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


# TODO
# make def for each type of HTTP request
# using:
# http://docs.python-requests.org/en/master/user/quickstart/

if __name__ == "__main__":

    print 'running main!'


# TODO
# argePArse not working right
#  http://newcoder.io/api/part-4/
