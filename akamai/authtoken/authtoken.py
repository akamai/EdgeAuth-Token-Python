# -*- coding: utf-8 -*-


# Copyright 2017 Akamai Technologies http://developer.akamai.com.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


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


class AuthTokenError(Exception):
    def __init__(self, text):
        self._text = text

    def __str__(self):
        return 'AuthTokenError:{0}'.format(self._text)

    def _getText(self):
        return str(self)
    text = property(_getText, None, None,
        'Formatted error text.')


class AuthToken:
    def __init__(self, token_type=None, token_name='__token__',
                 key=None, algorithm='sha256', salt=None,
                 start_time=None, end_time=None, window_seconds=None,
                 field_delimiter='~', acl_delimiter='!',
                 escape_early=False, escape_early_upper=False, verbose=False):
        
        self.token_type = token_type
        self.token_name = token_name
        self.start_time = start_time
        self.end_time = end_time
        self.window_seconds = window_seconds
        if key is None or len(key) <= 0:
            raise AuthTokenError('You must provide a secret in order to '
                'generate a new token.')
        self.key = key
        self.algorithm = algorithm
        self.salt = salt
        self.field_delimiter = field_delimiter
        self.acl_delimiter = acl_delimiter
        self.escape_early = escape_early
        self.escape_early_upper = escape_early_upper
        self.verbose = verbose

    def escapeEarly(self, text):
        if self.escape_early or self.escape_early_upper:
            # Only escape the text if we are configured for escape early.
            new_text = quote_plus(text)
            if self.escape_early_upper:
                def toUpper(match):
                    return match.group(1).upper()
                return re.sub(r'(%..)', toUpper, new_text)
            else:
                def toLower(match):
                    return match.group(1).lower()
                return re.sub(r'(%..)', toLower, new_text)

        # Return the original, unmodified text.
        return text

    def _generateToken(self, url=None, acl=None,
                       window_seconds=None, start_time=None, end_time=None,
                       ip=None, payload=None, session_id=None):
        if str(start_time).lower() == 'now':
            # Initialize the start time if we are asked for a starting time of
            # now.
            start_time = int(time.mktime(time.gmtime()))
        elif start_time is not None:
            try:
                start_time = int(start_time)
            except:
                raise AuthTokenError('start_time must be numeric or now')

        if end_time is not None:
            try:
                end_time = int(end_time)
            except:
                raise AuthTokenError('end_time must be numeric.')

        if window_seconds is not None:
            try:
                window_seconds = int(window_seconds)
            except:
                raise AuthTokenError('window_seconds must be numeric.')

        if end_time is None:
            if int(window_seconds or 0) > 0:
                if start_time is None:
                    # If we have a window window without a start time,
                    # calculate the end time starting from the current time.
                    end_time = int(time.mktime(time.gmtime())) + \
                        window_seconds
                else:
                    end_time = start_time + window_seconds
            else:
                raise AuthTokenError('You must provide an expiration time or '
                    'a duration window..')
        
        try:
            if end_time < start_time:
                raise AuthTokenError('Token will have already expired.')
        except TypeError:
            pass
        
        if ((acl is None and url is None) or
            acl is not None and url is not None and
            (len(acl) <= 0) and (len(url) <= 0)):
            raise AuthTokenError('You must provide a URL or an ACL.')

        if (acl is not None and url is not None and
            (len(acl) > 0) and (len(url) > 0)):
            raise AuthTokenError('You must provide a URL OR an ACL, '
                'not both.')

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
    self.acl_delimiter if self.acl_delimiter else '', #6
    self.escape_early if self.escape_early else '', #7
    start_time if start_time else '', #8
    end_time if end_time else '', #9
    window_seconds if window_seconds else '', #10
    ip if ip else '', #11
    url if url else '', #12
    acl if acl else '', #13
    payload if payload else '', #14
    session_id if session_id else '')) #15

        hash_source = ''
        new_token = ''

        if ip:
            new_token += 'ip={0}{1}'.format(self.escapeEarly(ip),
                self.field_delimiter)

        if start_time is not None:
            new_token += 'st={0}{1}'.format(start_time, self.field_delimiter)

        new_token += 'exp={0}{1}'.format(end_time, self.field_delimiter)

        if acl:
            new_token += 'acl={0}{1}'.format(acl, self.field_delimiter)

        if session_id:
            new_token += 'id={0}{1}'.format(self.escapeEarly(session_id), self.field_delimiter)

        if payload:
            new_token += 'data={0}{1}'.format(self.escapeEarly(payload), self.field_delimiter)

        hash_source += new_token
        if url and not acl:
            hash_source += 'url={0}{1}'.format(self.escapeEarly(url), self.field_delimiter)

        if self.salt:
            hash_source += 'salt={0}{1}'.format(self.salt, self.field_delimiter)

        if self.algorithm.lower() not in ('sha256', 'sha1', 'md5'):
            raise AuthTokenError('Unknown algorithm')

        token_hmac = hmac.new(
            binascii.a2b_hex(self.key.encode()),
            hash_source.rstrip(self.field_delimiter).encode(),
            getattr(hashlib, self.algorithm.lower())).hexdigest()
        new_token += 'hmac={0}'.format(token_hmac)

        return new_token

    def generateToken(self, url=None, acl=None, start_time=None, end_time=None, window_seconds=None,
                      ip=None, payload=None, session_id=None):
        if not start_time:
            start_time = self.start_time
        
        if not end_time:
            end_time = self.end_time
        
        if not window_seconds:
            window_seconds = self.window_seconds

        return self._generateToken(url=url,
                                   acl=acl,
                                   start_time=start_time,
                                   end_time=end_time,
                                   window_seconds=window_seconds,
                                   ip=ip,
                                   payload=payload,
                                   session_id=session_id)