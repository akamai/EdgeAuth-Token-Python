Akamai-EdgeAuth: Akamai Edge Authorization Token for Python
=================================================

.. image:: https://img.shields.io/pypi/v/akamai-edgeauth.svg
    :target: https://pypi.python.org/pypi/akamai-edgeauth

.. image:: https://travis-ci.org/AstinCHOI/Akamai-EdgeAuth-Python.svg?branch=master
    :target: https://travis-ci.org/AstinCHOI/Akamai-EdgeAuth-Python

.. image:: http://img.shields.io/:license-apache-blue.svg 
    :target: https://github.com/AstinCHOI/Akamai-EdgeAuth-Python/blob/master/LICENSE


Akamai-EdgeAuth is Akamai Edge Authorization Token in the HTTP Cookie, Query String and Header for a client.
You can configure it in the Property Manager at https://control.akamai.com.
It's a behavior which is Auth Token 2.0 Verification.  

Akamai-EdgeAuth supports Python 2.6–2.7 & 3.3–3.6, and runs great on PyPy. (This is Akamai unofficial code)


.. image:: https://github.com/AstinCHOI/akamai-asset/blob/master/edgeauth/edgeauth.png?raw=true
    :align: center


Installation
------------

To install Akamai Edge Authorization Token for Python:  

.. code-block:: bash

    $ pip install akamai-edgeauth


Example
-------

    .. code-block:: python

        from akamai.edgeauth import EdgeAuth, EdgeAuthError
        import requests # just for this example

        AT_HOSTNAME = 'edgeauth.akamaized.net'
        AT_ENCRYPTION_KEY = 'YourEncryptionKey' 
        DURATION = 500 # seconds

    ::

        AT_ENCRYPTION_KEY must be hexadecimal digit string with even-length.
        Don't expose AT_ENCRYPTION_KEY on the public repository.

**URL parameter option**

    .. code-block:: python

        # 1) Cookie
        at = EdgeAuth(key=AT_ENCRYPTION_KEY, window_seconds=DURATION, escape_early=True)
        token = at.generateToken(url="/akamai/edgeauth")
        url = "http://{0}{1}".format(AT_HOSTNAME, "/akamai/edgeauth")
        response = requests.get(url, cookies={at.token_name: token})
        print(response) # Maybe not 403

        # 2) Query string
        token = at.generateToken(url="/akamai/edgeauth")
        url = "http://{0}{1}?{2}={3}".format(AT_HOSTNAME, "/akamai/edgeauth", at.token_name, token)
        response = requests.get(url)
        print(response)

    ::

        It depends on turning on/off 'Escape token input' in the property manager. (on: escape_early=True / off: escape_early=False)
        In [Example 2], it's only okay for 'Ignore query string' option on in the property manager.
        If you want to 'Ignore query string' off using query string as your token, Please contact your Akamai representative.


**ACL(Access Control List) parameter option**

    .. code-block:: python

        # 1) Header using *
        at = EdgeAuth(key=AT_ENCRYPTION_KEY, window_seconds=DURATION)
        token = at.generateToken(acl="/akamai/edgeauth/list/*")
        url = "http://{0}{1}".format(AT_HOSTNAME, "/akamai/edgeauth/list/something")
        response = requests.get(url, headers={at.token_name: token})
        print(response)

        # 2) Cookie Delimited by '!'
        acl = ["/akamai/edgeauth", "/akamai/edgeauth/list/*"]
        token = at.generateToken(acl=EdgeAuth.ACL_DELIMITER.join(acl))
        url = "http://{0}{1}".format(AT_HOSTNAME, "/akamai/edgeauth/list/something2")
            # or "/akamai/edgeauth"
        response = requests.get(url, cookies={at.token_name: token})
        print(response)

    ::

        It doesn't matter turning on/off 'Escape token input' in the property manager, but you should keep escape_early=False (Default)
    

Usage
-----
**EdgeAuth Class**

.. code-block:: python

    EdgeAuth(token_type=None, token_name='__token__', key=None, algorithm='sha256', 
            salt=None, start_time=None, end_time=None, window_seconds=None,
            field_delimiter='~', escape_early=False, verbose=False)

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
     escape_early          Causes strings to be 'url' encoded before being used.
     verbose               Print all parameters.
    ====================  ===================================================================================================

**EdgeAuth's Static Variable**

.. code-block:: python

    ACL_DELIMITER = '!' # Character used to delimit acl fields.


**EdgeAuth's Method**

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
    | end_time       | Same as Authtoken's parameters, but they overrides Authtoken's.                                         |
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

    $ python cms_edgeauth.py -k YourEncryptionKey -w 5000 -u /hello/world -x

Use -h or --help option for the detail.