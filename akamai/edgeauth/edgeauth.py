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
    ACL_DELIMITER='!'
    
    def __init__(self, token_type=None, token_name='__token__',
                 key=None, algorithm='sha256', salt=None,
                 start_time=None, end_time=None, window_seconds=None,
                 field_delimiter='~', escape_early=False, verbose=False):
        
        self.token_type = token_type
        self.token_name = token_name
        self.start_time = start_time
        self.end_time = end_time
        self.window_seconds = window_seconds
        if key is None or len(key) <= 0:
            raise EdgeAuthError('You must provide a secret in order to '
                'generate a new token.')
        self.key = key
        self.algorithm = algorithm
        self.salt = salt
        self.field_delimiter = field_delimiter
        self.escape_early = escape_early
        self.verbose = verbose

    def _escapeEarly(self, text):
        if self.escape_early:
            def toLower(match):
                return match.group(1).lower()
            return re.sub(r'(%..)', toLower, quote_plus(text))
        else:
            return text

    def generateToken(self, url=None, acl=None, start_time=None, 
                       end_time=None, window_seconds=None,
                       ip=None, payload=None, session_id=None):
        if not start_time:
            start_time = self.start_time
        if not end_time:
            end_time = self.end_time
        if not window_seconds:
            window_seconds = self.window_seconds

        if str(start_time).lower() == 'now':
            start_time = int(time.mktime(time.gmtime()))
        elif start_time:
            try:
                if int(start_time) <= 0:
                    raise EdgeAuthError('start_time must be ( > 0 )')    
            except:
                raise EdgeAuthError('start_time must be numeric or now')

        if end_time:
            try:
                if int(end_time) <= 0:
                    raise EdgeAuthError('end_time must be ( > 0 )')
            except:
                raise EdgeAuthError('end_time must be numeric')

        if window_seconds:
            try:
                if int(window_seconds) <= 0:
                    raise EdgeAuthError('window_seconds must be ( > 0 )')    
            except:
                raise EdgeAuthError('window_seconds must be numeric')
                
        if end_time is None:
            if window_seconds:
                if start_time is None:
                    # If we have a window_seconds without a start time,
                    # calculate the end time starting from the current time.
                    end_time = int(time.mktime(time.gmtime())) + \
                        window_seconds
                else:
                    end_time = start_time + window_seconds
            else:
                raise EdgeAuthError('You must provide an expiration time or '
                    'a duration window ( > 0 )')
        
        if start_time and (end_time <= start_time):
            raise EdgeAuthError('Token will have already expired.')
        
        if (not acl and not url) or (acl and url):
            raise EdgeAuthError('You must provide a URL or an ACL')

        if self.verbose:
            print('''
Akamai Token Generation Parameters
Token Type      : {0}
Token Name      : {1}
Start Time      : {8}
End Time        : {9}
Window(seconds) : {10}
IP              : {11}
URL             : {12}
ACL             : {13}
Key/Secret      : {2}
Payload         : {14}
Algo            : {3}
Salt            : {4}
Session ID      : {15}
Field Delimiter : {5}
ACL Delimiter   : {6}
Escape Early    : {7}
Generating token...'''.format(self.token_type if self.token_type else '', #0
                            self.token_name if self.token_name else '', #1
                            self.key if self.key else '', #2
                            self.algorithm if self.algorithm else '', #3
                            self.salt if self.salt else '', #4
                            self.field_delimiter if self.field_delimiter else '', #5
                            ACL_DELIMITER if ACL_DELIMITER else '', #6
                            self.escape_early if self.escape_early else '', #7
                            start_time if start_time else '', #8
                            end_time if end_time else '', #9
                            window_seconds if window_seconds else '', #10
                            ip if ip else '', #11
                            url if url else '', #12
                            acl if acl else '', #13
                            payload if payload else '', #14
                            session_id if session_id else '')) #15

        hash_source = []
        new_token = []

        if ip:
            new_token.append('ip={0}'.format(self._escapeEarly(ip)))

        if start_time:
            new_token.append('st={0}'.format(start_time))

        new_token.append('exp={0}'.format(end_time))

        if acl:
            new_token.append('acl={0}'.format(acl))

        if session_id:
            new_token.append('id={0}'.format(self._escapeEarly(session_id)))

        if payload:
            new_token.append('data={0}'.format(self._escapeEarly(payload)))

        hash_source = list(new_token)
        if url and not acl:
            hash_source.append('url={0}'.format(self._escapeEarly(url)))

        if self.salt:
            hash_source.append('salt={0}'.format(self.salt))

        if self.algorithm.lower() not in ('sha256', 'sha1', 'md5'):
            raise EdgeAuthError('Unknown algorithm')

        token_hmac = hmac.new(
            binascii.a2b_hex(self.key.encode()),
            self.field_delimiter.join(hash_source).encode(),
            getattr(hashlib, self.algorithm.lower())).hexdigest()
        new_token.append('hmac={0}'.format(token_hmac))

        return self.field_delimiter.join(new_token)