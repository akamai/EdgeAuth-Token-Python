# -*- coding: utf-8 -*-

# Copyright (c) 2017, Akamai Technologies, Inc.
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Akamai Technologies nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL AKAMAI TECHNOLOGIES BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import binascii
import hashlib
import hmac
import optparse
import os
import re
import sys
import time
if sys.version_info[0] >= 3:
    from urllib.parse import quote_plus, quote
else:
    from urllib import quote_plus, quote

# Force the local timezone to be GMT.
os.environ['TZ'] = 'GMT'


class AkamaiTokenError(Exception):
    def __init__(self, text):
        self._text = text

    def __str__(self):
        return 'AkamaiTokenError:%s' % self._text

    def _getText(self):
        return str(self)
    text = property(_getText, None, None,
        'Formatted error text.')


class TokenAuth:
    def __init__(self, token_type=None, token_name='__token__',
                 key=None, algorithm='sha256', salt=None,
                 start_time=None, end_time=None, duration=None,
                 field_delimiter='~', acl_delimiter='!',
                 escape_early=True, escape_early_upper=False, debug=False):
        
        self.token_type = token_type
        self.token_name = token_name
        self.start_time = start_time
        self.end_time = end_time
        self.duration = duration
        if key is None or len(key) <= 0:
            raise AkamaiTokenError('You must provide a secret in order to '
                'generate a new token.')
        self.key = key
        self.algorithm = algorithm
        self.salt = salt
        self.field_delimiter = field_delimiter
        self.acl_delimiter = acl_delimiter
        self.escape_early = escape_early
        self.escape_early_upper = escape_early_upper
        self.debug = debug

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

    def _generateToken(self, url=None, 
                       acl=None, acl_delimiter=None,
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
                raise AkamaiTokenError('start_time must be numeric or now')

        if end_time is not None:
            try:
                end_time = int(end_time)
            except:
                raise AkamaiTokenError('end_time must be numeric.')

        if window_seconds is not None:
            try:
                window_seconds = int(window_seconds)
            except:
                raise AkamaiTokenError('window_seconds must be numeric.')

        if end_time is None:
            if int(window_seconds or 0) > 0:
                if start_time is None:
                    # If we have a duration window without a start time,
                    # calculate the end time starting from the current time.
                    end_time = int(time.mktime(time.gmtime())) + \
                        window_seconds
                else:
                    end_time = start_time + window_seconds
            else:
                raise AkamaiTokenError('You must provide an expiration time or '
                    'a duration window.')
        
        try:
            if end_time < start_time:
                raise AkamaiTokenError('Token will have already expired.')
        except TypeError:
            pass
        
        if ((acl is None and url is None) or
            acl is not None and url is not None and
            (len(acl) <= 0) and (len(url) <= 0)):
            raise AkamaiTokenError('You must provide a URL or an ACL.')

        if (acl is not None and url is not None and
            (len(acl) > 0) and (len(url) > 0)):
            raise AkamaiTokenError('You must provide a URL OR an ACL, '
                'not both.')

        if self.debug:
            print('''
Akamai Token Generation Parameters
Token Type      : %s
Token Name      : %s
Start Time      : %s
Window(seconds) : %s
End Time        : %s
IP              : %s
URL             : %s
ACL             : %s
Key/Secret      : %s
Payload         : %s
Algo            : %s
Salt            : %s
Session ID      : %s
Field Delimiter : %s
ACL Delimiter   : %s
Escape Early    : %s
Generating token...''' % (
    ''.join([str(x) for x in [self.token_type] if x is not None]),
    ''.join([str(x) for x in [self.token_name] if x is not None]),
    ''.join([str(x) for x in [start_time] if x is not None]),
    ''.join([str(x) for x in [window_seconds] if x is not None]),
    ''.join([str(x) for x in [end_time] if x is not None]),
    ''.join([str(x) for x in [ip] if x is not None]),
    ''.join([str(x) for x in [url] if x is not None]),
    ''.join([str(x) for x in [acl] if x is not None]),
    ''.join([str(x) for x in [self.key] if x is not None]),
    ''.join([str(x) for x in [payload] if x is not None]),
    ''.join([str(x) for x in [self.algorithm] if x is not None]),
    ''.join([str(x) for x in [self.salt] if x is not None]),
    ''.join([str(x) for x in [session_id] if x is not None]),
    ''.join([str(x) for x in [self.field_delimiter] if x is not None]),
    ''.join([str(x) for x in [acl_delimiter] if x is not None]),
    ''.join([str(x) for x in [self.escape_early] if x is not None])))

        hash_source = ''
        new_token = ''

        if ip:
            new_token += 'ip=%s%c' % (self.escapeEarly(ip),
                self.field_delimiter)

        if start_time is not None:
            new_token += 'st=%d%c' % (start_time, self.field_delimiter)

        new_token += 'exp=%d%c' % (end_time, self.field_delimiter)

        if acl:
            new_token += 'acl=%s%c' % (self.escapeEarly(acl),
                self.field_delimiter)

        if session_id:
            new_token += 'id=%s%c' % (self.escapeEarly(session_id),
                self.field_delimiter)

        if payload:
            new_token += 'data=%s%c' % (self.escapeEarly(payload),
                self.field_delimiter)

        hash_source += new_token
        if url and not acl:
            hash_source += 'url=%s%c' % (self.escapeEarly(url),
                self.field_delimiter)

        if self.salt:
            hash_source += 'salt=%s%c' % (self.salt, self.field_delimiter)

        if self.algorithm.lower() not in ('sha256', 'sha1', 'md5'):
            raise AkamaiTokenError('Unknown algorithm')

        token_hmac = hmac.new(
            binascii.a2b_hex(self.key),
            hash_source.rstrip(self.field_delimiter).encode(),
            getattr(hashlib, self.algorithm.lower())).hexdigest()
        new_token += 'hmac=%s' % token_hmac

        return '%s=%s' % (self.token_name, new_token)

    def generateToken(self, url=None, acl=None, start_time=None, end_time=None, duration=None,
                      ip=None, payload=None, session_id=None):
        if not start_time:
            start_time = self.start_time
        
        if not end_time:
            end_time = self.end_time
        
        if not duration:
            duration = self.duration

        return self._generateToken(url=url,
                                   acl=acl,
                                   start_time=start_time,
                                   end_time=end_time,
                                   window_seconds=duration,
                                   ip=ip,
                                   payload=payload,
                                   session_id=session_id)