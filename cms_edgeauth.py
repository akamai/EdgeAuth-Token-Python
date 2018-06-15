import binascii
import hashlib
import hmac
import optparse
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
        start_time = self.start_time
        end_time = self.end_time

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

        if self.window_seconds:
            try:
                if int(self.window_seconds) <= 0:
                    raise EdgeAuthError('window_seconds must be ( > 0 )')
            except:
                raise EdgeAuthError('window_seconds must be numeric')
                
        if end_time is None:
            if self.window_seconds:
                if start_time is None:
                    # If we have a window_seconds without a start time,
                    # calculate the end time starting from the current time.
                    end_time = int(time.mktime(time.gmtime())) + \
                        self.window_seconds
                else:
                    end_time = start_time + self.window_seconds
            else:
                raise EdgeAuthError('You must provide an expiration time or '
                    'a duration window ( > 0 )')
        
        if start_time and (end_time <= start_time):
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
                            start_time if start_time else '',
                            end_time if end_time else '',
                            self.window_seconds if self.window_seconds else '',
                            self.field_delimiter if self.field_delimiter else '',
                            self.acl_delimiter if self.acl_delimiter else '',
                            self.escape_early if self.escape_early else '',
                            ('url: ' if is_url else 'acl: ') + path))

        hash_source = []
        new_token = []

        if self.ip:
            new_token.append('ip={0}'.format(self._escape_early(self.ip)))

        if start_time:
            new_token.append('st={0}'.format(start_time))

        new_token.append('exp={0}'.format(end_time))

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

        if self.algorithm.lower() not in ('sha256', 'sha1', 'md5'):
            raise EdgeAuthError('Unknown algorithm')

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
            raise EdgeAuthError('You must provide url')
        return self._generate_token(url, True)


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option(
        '-t', '--token_type',
        action='store', type='string', dest='token_type',
        help='Select a preset. (Not Supported Yet)')
    parser.add_option(
        '-n', '--token_name',
        action='store', default='__token__', type='string', dest='token_name',
        help='Parameter name for the new token. [Default: __token__]')
    parser.add_option(
        '-k', '--key',
        action='store', type='string', dest='key',
        help='Secret required to generate the token. It must be hexadecimal digit string with even-length.')
    parser.add_option(
        '-A', '--algo',
        action='store', type='string', dest='algorithm', default='sha256',
        help='Algorithm to use to generate the token. (sha1, sha256, or md5) [Default:sha256]')
    parser.add_option(
        '-S', '--salt',
        action='store', type='string', dest='salt',
        help='Additional data validated by the token but NOT included in the token body.')
    parser.add_option(
        '-s', '--start_time',
        action='store', type='string', dest='start_time',
        help="What is the start time? (Use 'now' for the current time)")
    parser.add_option(
        '-e', '--end_time',
        action='store', type='string', dest='end_time',
        help='When does this token expire? --end_time overrides --window')
    parser.add_option(
        '-w', '--window',
        action='store', type='int', dest='window_seconds',
        help='How long is this token valid for?')
    parser.add_option(
        '-d', '--field_delimiter',
        action='store', default='~', type='string', dest='field_delimiter',
        help='Character used to delimit token body fields. [Default:~]')
    parser.add_option(
        '-D', '--acl_delimiter',
        action='store', default='!', type='string', dest='acl_delimiter',
        help='Character used to delimit acl fields. [Default:!]')
    parser.add_option(
        '-x', '--escape_early',
        action='store_true', default=False, dest='escape_early',
        help='Causes strings to be url encoded before being used.')
    parser.add_option(
        '-v', '--verbose',
        action='store_true', default=False, dest='verbose',
        help='Print all arguments.')

    parser.add_option(
        '-u', '--url',
        action='store', type='string', dest='url',
        help='URL path. [Used for:URL]')
    parser.add_option(
        '-a', '--acl',
        action='store', type='string', dest='access_list',
        help='Access control list delimited by ! [ie. /*]')
    parser.add_option(
        '-i', '--ip',
        action='store', type='string', dest='ip_address',
        help='IP Address to restrict this token to. IP Address to restrict this token to. \
            (Troublesome in many cases (roaming, NAT, etc) so not often used)')
    parser.add_option(
        '-p', '--payload',
        action='store', type='string', dest='payload',
        help='Additional text added to the calculated digest.')
    parser.add_option(
        '-I', '--session_id',
        action='store', type='string', dest='session_id',
        help='The session identifier for single use tokens or other advanced cases.')

    (options, args) = parser.parse_args()

    generator = EdgeAuth(
        token_type=options.token_type,
        token_name=options.token_name,
        key=options.key,
        algorithm=options.algorithm,
        salt=options.salt,
        ip=options.ip_address,
        payload=options.payload,
        session_id=options.session_id,
        start_time=options.start_time,
        end_time=options.end_time,
        window_seconds=options.window_seconds,
        field_delimiter=options.field_delimiter,
        acl_delimiter=options.acl_delimiter,
        escape_early=options.escape_early,
        verbose=options.verbose)

    url=options.url
    acl=options.access_list

    if (url and acl):
        print("You should input one in the 'url' or the 'acl'.")
    else:
        if acl:
            token = generator.generate_acl_token(acl)
        else: # url
            token = generator.generate_url_token(url)

        print("### Cookie or Query String ###")
        print("{0}={1}".format(options.token_name, token))
        print("### Header ###")
        print("{0}: {1}".format(options.token_name, token))