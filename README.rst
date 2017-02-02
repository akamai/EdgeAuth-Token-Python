Akamai-AuthToken: Akamai Authorization for Python
=================================================

.. image:: http://img.shields.io/:license-apache-blue.svg 
    :target: https://github.com/AstinCHOI/Akamai-AuthToken-Python/blob/master/LICENSE

Akamai-AuthToken is Akamai Authorization Token in the HTTP Cookie, Query String and Header for a client. 
You can configure it in the Property Manager at https://control.akamai.com.
It's a behavior which is Auth Token 2.0 Verification.

.. image:: https://github.com/AstinCHOI/akamai-asset/blob/master/authtoken/authtoken.png?raw=true
    :align: center


Installation
------------

To install Akamai Authorization Token for Python:  

.. code-block:: bash

    $ pip install akamai-authtoken


Example
-------

.. code-block:: python

    >>> from akamai.authtoken import AuthToken, AuthTokenError
    >>> import requests # just for this example
    >>>
    >>> AA_HOSTNAME = 'token-auth.akamaized.net'
    >>> AA_ENCRYPTION_KEY = 'YourEncryptionKey' # Don't expose AA_ENCRYPTION_KEY on public repository.
    >>> window_seconds = 500
    >>>
    >>> at = AuthToken(key=AA_ENCRYPTION_KEY, window_seconds=window_seconds)
    >>> path = '/akamai/authtoken'
    >>> token = at.generateToken(url=path)
    >>> url = "http://{0}{1}".format(AA_HOSTNAME, '/akamai/authtoken')
    >>> response = requests.get(url, cookies={at.token_name: token})
    <Response [200]> # if fail, it will be 403
    >>>
    >>> path = '/akamai/authtoken/list/*'
    >>> token = at.generateToken(acl=path)
    >>> url = "http://{0}{1}".format(AA_HOSTNAME, '/akamai/authtoken/list/test')
    >>> response = requests.get(url, cookies={at.token_name: token})
    <Response [200]>
    >>> 
    >>>
    >>> # [INFO] AA_ENCRYPTION_KEY must be hexadecimal digit string with even-length.

Usage
-----
**AuthToken Class**

.. code-block:: python

    AuthToken(token_type=None, token_name='__token__', key=None, algorithm='sha256', 
            salt=None, start_time=None, end_time=None, window_seconds=None,
            field_delimiter='~', acl_delimiter='!', escape_early=True, 
            escape_early_upper=False, verbose=False)

::

    token_type - Select a preset. (Not Supported Yet)  
    token_name - Parameter name for the new token. [Default: __token__]
    key - Secret required to generate the token. It must be hexadecimal digit string with even-length.
    algorithm - Algorithm to use to generate the token. (sha1, sha256, or md5) [Default:sha256]
    salt - Additional data validated by the token but NOT included in the token body. (It will be deprecated)
    start_time - What is the start time? (Use string 'now' for the current time)
    end_time - When does this token expire? 'end_time' overrides 'window_seconds'
    window_seconds - How long is this token valid for?
    field_delimiter - Character used to delimit token body fields.
    acl_delimiter - Character used to delimit acl fields.
    escape_early - Causes strings to be url encoded before being used.
    escape_early_upper - Causes strings to be url encoded before being used.
    verbose - Print all arguments.


**AuthToken's Method**

.. code-block:: python

    generateToken(url=None, acl=None, start_time=None, end_time=None, 
                window_seconds=None, ip=None, payload=None, session_id=None)

::

    url - URL path
    acl - Access control list delimited by ! [ie. /*]
    start_time, end_time, window_seconds - Same as Authtoken's variables, but they overrides Authtoken's.
    ip - IP Address to restrict this token to. (Troublesome in many cases (roaming, NAT, etc) so not often used)
    payload - Additional text added to the calculated digest.
    session_id - The session identifier for single use tokens or other advanced cases.

    => This method returns Authorization Token string


Command
-------

.. code-block:: bash
    $ python cms_authtoken.py -k YourEncryptionKey -w 5000 -u /hello/world

Use -h or --help option for more detail.


Author
------

Astin Choi (achoi@akamai.com)  


License
-------

Copyright 2017 Akamai Technologies, Inc.  All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at `<http://www.apache.org/licenses/LICENSE-2.0>`_.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.