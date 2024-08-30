#!/usr/bin/env python3
'''personal data - first task'''
import re


def filter_datum(fields, redaction, message, seperator):
    '''returns the log message'''
    pattern = re.compile(r'(?<=^|{})({})(?={}|\s*$)'.format(
        re.escape(seperator), '|'.join(map(re.escape, fields)),
        re.escape(seperator)))
    return pattern.sub(redaction, message)
