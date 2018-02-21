# -*- coding: utf-8 -*-


import optparse

from akamai.edgeauth import EdgeAuth, EdgeAuthError


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
        action='store', type='string', dest='window_seconds',
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
        field_delimiter=options.field_delimiter,
        acl_delimiter=options.acl_delimiter,
        escape_early=options.escape_early,
        verbose=options.verbose)
    token = generator.generateToken(url=options.url,
                                    acl=options.access_list,
                                    start_time=options.start_time,
                                    end_time=options.end_time,
                                    window_seconds=options.window_seconds,
                                    ip=options.ip_address,
                                    payload=options.payload,
                                    session_id=options.session_id)

    print("### Cookie or Query String ###")
    print("{0}={1}".format(options.token_name, token))
    print("### Header ###")
    print("{0}: {1}".format(options.token_name, token))