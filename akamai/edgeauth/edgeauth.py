# -*- coding: utf-8 -*-

import binascii
import hashlib
import hmac
import os
import re
import sys
import time
if sys.version_info[0] >= 3:
    from urllib.parse import quote_plus
else:
    from urllib import quote_plus

# Force the local timezone to be GMT.
os.environ['TZ'] = 'GMT'


class EdgeAuthError(Exception):
    def __init__(self, text):
        self._text = text

    def __str__(self):
        return 'EdgeAuthError:{0}'.format(self._text)

    def _getText(self):
        return str(self)
    text = property(_getText, None, None,
        'Formatted error text.')


class EdgeAuth:
    def __init__(self, token_type=None, token_name='__token__',
                 key=None, algorithm='sha256', salt=None,
                 ip=None, payload=None, session_id=None,
                 start_time=None, end_time=None, window_seconds=None,
                 field_delimiter='~', acl_delimiter='!',
                 escape_early=False, verbose=False):
        
        if key is None or len(key) <= 0:
            raise EdgeAuthError('You must provide a secret in order to '
                'generate a new token.')

        if algorithm.lower() not in ('sha256', 'sha1', 'md5'):
            raise EdgeAuthError('Unknown algorithm')

        self.token_type = token_type
        self.token_name = token_name
        self.key = key
        self.algorithm = algorithm
        self.salt = salt
        self.ip = ip
        self.payload = payload
        self.session_id = session_id
        self.start_time = start_time
        self.end_time = end_time
        self.window_seconds = window_seconds
        self.field_delimiter = field_delimiter
        self.acl_delimiter = acl_delimiter
        self.escape_early = escape_early
        self.verbose = verbose

    def _escape_early(self, text):
        if self.escape_early:
            def toLower(match):
                return match.group(1).lower()
            return re.sub(r'(%..)', toLower, quote_plus(text))
        else:
            return text

    def _generate_token(self, path, is_url):
        if str(self.start_time).lower() == 'now':
            self.start_time = int(time.mktime(time.gmtime()))
        elif self.start_time:
            try:
                if int(self.start_time) <= 0:
                    raise EdgeAuthError('start_time must be ( > 0 )')    
            except:
                raise EdgeAuthError('start_time must be numeric or now')

        if self.end_time:
            try:
                if int(self.end_time) <= 0:
                    raise EdgeAuthError('end_time must be ( > 0 )')
            except:
                raise EdgeAuthError('end_time must be numeric')

        if self.window_seconds:
            try:
                if int(self.window_seconds) <= 0:
                    raise EdgeAuthError('window_seconds must be ( > 0 )')
            except:
                raise EdgeAuthError('window_seconds must be numeric')
                
        if self.end_time is None:
            if self.window_seconds:
                if self.start_time is None:
                    # If we have a window_seconds without a start time,
                    # calculate the end time starting from the current time.
                    self.end_time = int(time.mktime(time.gmtime())) + \
                        self.window_seconds
                else:
                    self.end_time = self.start_time + self.window_seconds
            else:
                raise EdgeAuthError('You must provide an expiration time or '
                    'a duration window ( > 0 )')
        
        if self.start_time and (self.end_time <= self.start_time):
            raise EdgeAuthError('Token will have already expired.')

        if self.verbose:
            print('''
Akamai Token Generation Parameters
Token Type      : {0}
Token Name      : {1}
Key/Secret      : {2}
Algo            : {3}
Salt            : {4}
IP              : {5}
Payload         : {6}
Session ID      : {7}
Start Time      : {8}
End Time        : {9}
Window(seconds) : {10}
Field Delimiter : {11}
ACL Delimiter   : {12}
Escape Early    : {13}
PATH            : {14}
Generating token...'''.format(self.token_type if self.token_type else '',
                            self.token_name if self.token_name else '',
                            self.key if self.key else '',
                            self.algorithm if self.algorithm else '',
                            self.salt if self.salt else '',
                            self.ip if self.ip else '',
                            self.payload if self.payload else '',
                            self.session_id if self.session_id else '',
                            self.start_time if self.start_time else '',
                            self.end_time if self.end_time else '',
                            self.window_seconds if self.window_seconds else '',
                            self.field_delimiter if self.field_delimiter else '',
                            self.acl_delimiter if self.acl_delimiter else '',
                            self.escape_early if self.escape_early else '',
                            ('url: ' if is_url else 'acl: ') + path))

        hash_source = []
        new_token = []

        if self.ip:
            new_token.append('ip={0}'.format(self._escape_early(ip)))

        if self.start_time:
            new_token.append('st={0}'.format(self.start_time))

        new_token.append('exp={0}'.format(self.end_time))

        if not is_url:
            new_token.append('acl={0}'.format(path))

        if self.session_id:
            new_token.append('id={0}'.format(self._escape_early(self.session_id)))

        if self.payload:
            new_token.append('data={0}'.format(self._escape_early(self.payload)))

        hash_source = list(new_token)
        if is_url:
            hash_source.append('url={0}'.format(self._escape_early(path)))

        if self.salt:
            hash_source.append('salt={0}'.format(self.salt))

        token_hmac = hmac.new(
            binascii.a2b_hex(self.key.encode()),
            self.field_delimiter.join(hash_source).encode(),
            getattr(hashlib, self.algorithm.lower())).hexdigest()
        new_token.append('hmac={0}'.format(token_hmac))

        return self.field_delimiter.join(new_token)

    def generate_acl_token(self, acl):
        if not acl:
            raise EdgeAuthError('You must provide acl')
        elif isinstance(acl, list):
            acl = self.acl_delimiter.join(acl)
        return self._generate_token(acl, False)

    def generate_url_token(self, url):
        if not url:
            raise EdgeAuthError('You must provide acl')
        return self._generate_token(url, True)