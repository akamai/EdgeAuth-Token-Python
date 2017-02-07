Akamai-AuthToken: Akamai Authorization for Python
=================================================

.. image:: https://img.shields.io/pypi/v/akamai-authtoken.svg
    :target: https://pypi.python.org/pypi/akamai-authtoken

.. image:: https://travis-ci.org/AstinCHOI/Akamai-AuthToken-Python.svg?branch=master
    :target: https://travis-ci.org/AstinCHOI/Akamai-AuthToken-Python

.. image:: http://img.shields.io/:license-apache-blue.svg 
    :target: https://github.com/AstinCHOI/Akamai-AuthToken-Python/blob/master/LICENSE


Akamai-AuthToken is Akamai Authorization Token in the HTTP Cookie, Query String and Header for a client. 
You can configure it in the Property Manager at https://control.akamai.com.
It's a behavior which is Auth Token 2.0 Verification.
Akamai-AuthToken supports Python 2.6–2.7 & 3.3–3.6, and runs great on PyPy.

.. image:: https://github.com/AstinCHOI/akamai-asset/blob/master/authtoken/authtoken.png?raw=true
    :align: center


Installation
------------

To install Akamai Authorization Token for Python:  

.. code-block:: bash

    $ pip install akamai-authtoken


Example
-------

.. topic:: Define

    .. code-block:: python

        from akamai.authtoken import AuthToken, AuthTokenError
        import requests # just for this example

        AA_HOSTNAME = 'auth-token.akamaized.net'
        AA_ENCRYPTION_KEY = 'YourEncryptionKey' 
        DURATION = 500 # seconds

    ::

        AA_ENCRYPTION_KEY must be hexadecimal digit string with even-length.
        Don't expose AA_ENCRYPTION_KEY on the public repository.

.. topic:: URL parameter option

    .. code-block:: python

        # 1) Cookie
        at = AuthToken(key=AA_ENCRYPTION_KEY, window_seconds=DURATION, escape_early=True)
        token = at.generateToken(url="/akamai/authtoken")
        url = "http://{0}{1}".format(AA_HOSTNAME, "/akamai/authtoken")
        response = requests.get(url, cookies={at.token_name: token})
        print(response)
        # <Response [200, 404 or 5xx]> # if fail, it will be 403

        # 2) Query string
        at = AuthToken(key=AA_ENCRYPTION_KEY, window_seconds=DURATION, escape_early=True)
        token = at.generateToken(acl="/akamai/authtoken")
        url = "http://{0}{1}?{2}={3}".format(AA_HOSTNAME, "/akamai/authtoken", at.token_name, token)
        response = requests.get(url)
        print(response)

    ::

        It depends on turning on/off 'Escape token input' in the property manager. (on: escape_early=True / off: escape_early=False)
        In [Example 2], it's only okay for 'Ignore query string' option on in the property manager.
        If you want to 'Ignore query string' off using query string as your token, Please contact your Akamai representative.


.. topic:: ACL(Access Control List) parameter option

    .. code-block:: python

        # 1) Header using *
        at = AuthToken(key=AA_ENCRYPTION_KEY, window_seconds=DURATION)
        token = at.generateToken(acl="/akamai/authtoken/list/*")
        url = "http://{0}{1}".format(AA_HOSTNAME, "/akamai/authtoken/list/something")
        response = requests.get(url, headers={at.token_name: token})
        print(response)

        # 2) Cookie Delimited by '!'
        at = AuthToken(key=AA_ENCRYPTION_KEY, window_seconds=DURATION)
        token = at.generateToken(acl="/akamai/authtoken/list!/akamai/authtoken/list/*")
        url = "http://{0}{1}".format(AA_HOSTNAME, "/akamai/authtoken/list/something2")
        response = requests.get(url, cookies={at.token_name: token})
        print(response)

    ::

        It doesn't matter turning on/off 'Escape token input' in the property manager, but you should keep escape_early=False (Default)
    

Usage
-----
**AuthToken Class**

.. code-block:: python

    AuthToken(token_type=None, token_name='__token__', key=None, algorithm='sha256', 
            salt=None, start_time=None, end_time=None, window_seconds=None,
            field_delimiter='~', acl_delimiter='!', escape_early=False, 
            escape_early_upper=False, verbose=False)

#

    ====================  ===================================================================================================
     Parameter             Description
    ====================  ===================================================================================================
     token_type            Select a preset. (Not Supported Yet)  
     token_name            Parameter name for the new token. [Default: __token__]
     key                   Secret required to generate the token. It must be hexadecimal digit string with even-length.
     algorithm             Algorithm to use to generate the token. (sha1, sha256, or md5) [Default:sha256]
     salt                  Additional data validated by the token but NOT included in the token body. (It will be deprecated)
     start_time            What is the start time? (Use string 'now' for the current time)
     end_time              When does this token expire? 'end_time' overrides 'window_seconds'
     window_seconds        How long is this token valid for?
     field_delimiter       Character used to delimit token body fields. [Default: ~]
     acl_delimiter         Character used to delimit acl fields. [Default: !]
     escape_early          Causes strings to be 'url' encoded before being used.
     escape_early_upper    Causes strings to be 'url' encoded before being used.
     verbose               Print all parameters.
    ====================  ===================================================================================================

**AuthToken's Method**

.. code-block:: python

    generateToken(url=None, acl=None, start_time=None, end_time=None, 
                window_seconds=None, ip=None, payload=None, session_id=None)

# Returns the authorization token string.

    +----------------+---------------------------------------------------------------------------------------------------------+
    | Parameter      | Description                                                                                             |
    +================+=========================================================================================================+
    | url            | Single URL path.                                                                                        |
    +----------------+---------------------------------------------------------------------------------------------------------+
    | acl            | Access control list delimited by ! [ie. /\*]                                                            |
    +----------------+---------------------------------------------------------------------------------------------------------+
    | start_time     |                                                                                                         |
    +----------------+                                                                                                         +
    | end_time       | Same as Authtoken's variables, but they overrides Authtoken's.                                          |
    +----------------+                                                                                                         +
    | window_seconds |                                                                                                         |
    +----------------+---------------------------------------------------------------------------------------------------------+
    | ip             | IP Address to restrict this token to. (Troublesome in many cases (roaming, NAT, etc) so not often used) |
    +----------------+---------------------------------------------------------------------------------------------------------+
    | payload        | Additional text added to the calculated digest.                                                         |
    +----------------+---------------------------------------------------------------------------------------------------------+
    | session_id     | The session identifier for single use tokens or other advanced cases.                                   |
    +----------------+---------------------------------------------------------------------------------------------------------+


Command
-------

.. code-block:: bash

    $ python cms_authtoken.py -k YourEncryptionKey -w 5000 -u /hello/world -x

Use -h or --help option for the detail.


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