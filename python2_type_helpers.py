#!/usr/bin/env python2

"""
Helper functions to verify that an object is a certian type by changing the
type is it is not what is wanted
"""



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

