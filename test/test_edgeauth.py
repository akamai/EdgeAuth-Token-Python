# -*- coding: utf-8 -*-


import os
import sys
import unittest

sys.path.append("akamai/edgeauth")
sys.path.append("../akamai/edgeauth")
from edgeauth import EdgeAuth, EdgeAuthError

import requests


if 'TEST_MODE' in os.environ and os.environ['TEST_MODE'] == 'TRAVIS':
    AT_HOSTNAME = os.environ['AT_HOSTNAME']
    AT_ENCRYPTION_KEY = os.environ['AT_ENCRYPTION_KEY']
    AT_TRANSITION_KEY = os.environ['AT_TRANSITION_KEY']
    AT_SALT = os.environ['AT_SALT']
else:
    import secrets
    AT_HOSTNAME = secrets.AT_HOSTNAME
    AT_ENCRYPTION_KEY = secrets.AT_ENCRYPTION_KEY
    AT_TRANSITION_KEY = secrets.AT_TRANSITION_KEY    
    AT_SALT = secrets.AT_SALT

DEFAULT_WINDOW_SECONDS = 500


class TestEdgeAuth(unittest.TestCase):

    def setUp(self):
        # Test for Query String
        self.at = EdgeAuth(**{'key': AT_ENCRYPTION_KEY, 'window_seconds': DEFAULT_WINDOW_SECONDS})
        
        # Test for Cookie
        self.cat = EdgeAuth(key=AT_ENCRYPTION_KEY, algorithm='sha1', window_seconds=DEFAULT_WINDOW_SECONDS)

        # Test for Header
        self.hat = EdgeAuth(key=AT_ENCRYPTION_KEY, algorithm='md5', window_seconds=DEFAULT_WINDOW_SECONDS)

    def _token_setting(self, ttype, escape_early, transition):
        t = None
        if ttype == 'q':
            t = self.at
        elif ttype == 'c':
            t = self.cat
        elif ttype == 'h':
            t = self.hat
        
        if transition:
            t.key = AT_TRANSITION_KEY
        
        t.escape_early = escape_early

    def _queryAssertEqual(self, path, expacted, escape_early=False, transition=False,
                          payload=None, session_id=None, isUrl=True):
        self._token_setting('q', escape_early, transition)
        if isUrl:
            token = self.at.generateToken(url=path, payload=payload, session_id=session_id)
        else:
            token = self.at.generateToken(acl=path, payload=payload, session_id=session_id)
 
        url = "http://{0}{1}{4}{2}={3}".format(AT_HOSTNAME, path, self.at.token_name, token,
            '&' if '?' in path else '?')
        response = requests.get(url)
        self.assertEqual(expacted, response.status_code)
    
    def _cookieAssertEqual(self, path, expacted, escape_early=False, transition=False,
                           payload=None, session_id=None, isUrl=True):
        self._token_setting('c', escape_early, transition)
        if isUrl:
            token = self.cat.generateToken(url=path, payload=payload, session_id=session_id)
        else:
            token = self.cat.generateToken(acl=path, payload=payload, session_id=session_id)

        url = "http://{0}{1}".format(AT_HOSTNAME, path)
        response = requests.get(url, cookies={self.cat.token_name: token})
        self.assertEqual(expacted, response.status_code)

    def _headerAssertEqual(self, path, expacted, escape_early=False, transition=False,
                           payload=None, session_id=None, isUrl=True):
        self._token_setting('h', escape_early, transition)
        if isUrl:
            token = self.hat.generateToken(url=path, payload=payload, session_id=session_id)
        else:
            token = self.hat.generateToken(acl=path, payload=payload, session_id=session_id)

        url = "http://{0}{1}".format(AT_HOSTNAME, path)
        response = requests.get(url, headers={self.hat.token_name: token})
        self.assertEqual(expacted, response.status_code)
        
    def _test_case_set(self, query_path, cookie_path, header_path, escape_early, isUrl):
        # General Test
        self._queryAssertEqual(query_path, 404, escape_early=escape_early, isUrl=isUrl)
        self._cookieAssertEqual(cookie_path, 404, escape_early=escape_early, isUrl=isUrl)
        self._headerAssertEqual(header_path, 404, escape_early=escape_early, isUrl=isUrl)


        if isUrl:
            query_string="?foo=bar&hello=world"
            self._queryAssertEqual(query_path + query_string, 403, escape_early=(False==escape_early), isUrl=isUrl)
            self._cookieAssertEqual(cookie_path + query_string, 403, escape_early=(False==escape_early), isUrl=isUrl)
            self._headerAssertEqual(header_path + query_string, 403, escape_early=(False==escape_early), isUrl=isUrl)

        # Transition Key Test
        self._queryAssertEqual(query_path, 404, transition=True, escape_early=escape_early, isUrl=isUrl)
        self._cookieAssertEqual(cookie_path, 404, transition=True, escape_early=escape_early, isUrl=isUrl)
        self._headerAssertEqual(header_path, 404, transition=True, escape_early=escape_early, isUrl=isUrl)

        # Payload Test
        self._queryAssertEqual(query_path, 404, payload='SOME_PAYLOAD_DATA', escape_early=escape_early, isUrl=isUrl)
        self._cookieAssertEqual(cookie_path, 404, payload='SOME_PAYLOAD_DATA', escape_early=escape_early, isUrl=isUrl)
        self._headerAssertEqual(header_path, 404, payload='SOME_PAYLOAD_DATA', escape_early=escape_early, isUrl=isUrl)

        # Session Id Test
        self._queryAssertEqual(query_path, 404, session_id='SOME_SESSION_ID_DATA', escape_early=escape_early, isUrl=isUrl)
        self._cookieAssertEqual(cookie_path, 404, session_id='SOME_SESSION_ID_DATA', escape_early=escape_early, isUrl=isUrl)
        self._headerAssertEqual(header_path, 404, session_id='SOME_SESSION_ID_DATA', escape_early=escape_early, isUrl=isUrl)
    
    ##########
    # URL TEST
    ##########
    def test_url_escape_on__ignoreQuery_yes(self):
        self._test_case_set("/q_escape_ignore", "/c_escape_ignore", "/h_escape_ignore", escape_early=True, isUrl=True)

    def test_url_escape_off__ignoreQuery_yes(self):
        self._test_case_set("/q_ignore", "/c_ignore", "/h_ignore", escape_early=False, isUrl=True)

    def test_url_escape_on__ignoreQuery_no(self):
        query_path = "/q_escape"
        cookie_path = "/c_escape"
        header_path = "/h_escape"
        self._test_case_set(query_path, cookie_path, header_path, escape_early=True, isUrl=True)

        query_string="?foo=bar&hello=world"
        self._queryAssertEqual(query_path + query_string, 404, escape_early=True, isUrl=True)
        self._cookieAssertEqual(cookie_path + query_string, 404, escape_early=True, isUrl=True)
        self._headerAssertEqual(header_path + query_string, 404, escape_early=True, isUrl=True)

    def test_url_escape_off__ignoreQuery_no(self):
        query_path = "/q"
        cookie_path = "/c"
        header_path = "/h"
        self._test_case_set(query_path, cookie_path, header_path, escape_early=False, isUrl=True)
        
        query_string="?foo=bar&hello=world"
        self._queryAssertEqual(query_path + query_string, 404, escape_early=False, isUrl=True)
        self._cookieAssertEqual(cookie_path + query_string, 404, escape_early=False, isUrl=True)
        self._headerAssertEqual(header_path + query_string, 404, escape_early=False, isUrl=True)
    
    def test_url_query_escape_on__ignore_yes_with_salt(self):
        query_salt_path = "/salt"
        ats = EdgeAuth(key=AT_ENCRYPTION_KEY, salt=AT_SALT, window_seconds=DEFAULT_WINDOW_SECONDS, escape_early=True)
        token = ats.generateToken(url=query_salt_path)
        url = "http://{0}{1}?{2}={3}".format(AT_HOSTNAME, query_salt_path, ats.token_name, token)
        response = requests.get(url)
        self.assertEqual(404, response.status_code)
    ##########
    
    ##########
    # ACL TEST
    ##########
    def test_acl_escape_on__ignoreQuery_yes(self):
        self._test_case_set("/q_escape_ignore", "/c_escape_ignore", "/h_escape_ignore", escape_early=False, isUrl=False)

    def test_acl_escape_off__ignoreQuery_yes(self):
        self._test_case_set("/q_ignore", "/c_ignore", "/h_ignore", escape_early=False, isUrl=False)

    def test_acl_escape_on__ignoreQuery_no(self):
        self._test_case_set("/q_escape", "/c_escape", "/h_escape", escape_early=False, isUrl=False)

    def test_acl_escape_off__ignoreQuery_no(self):
        self._test_case_set("/q", "/c", "/h", escape_early=False, isUrl=False)
    
    def test_acl_asta_escape_on__ignoreQuery_yes(self):
        ata = EdgeAuth(key=AT_ENCRYPTION_KEY, window_seconds=DEFAULT_WINDOW_SECONDS, escape_early=False)
        token = ata.generateToken(acl='/q_escape_ignore/*')
        url = "http://{0}{1}?{2}={3}".format(AT_HOSTNAME, '/q_escape_ignore/hello', ata.token_name, token)
        response = requests.get(url)
        self.assertEqual(404, response.status_code)
    
    def test_acl_deli_escape_on__ignoreQuery_yes(self):
        atd = EdgeAuth(key=AT_ENCRYPTION_KEY, window_seconds=DEFAULT_WINDOW_SECONDS, escape_early=False)
        acl = ['/q_escape_ignore', '/q_escape_ignore/*']
        token = atd.generateToken(acl=EdgeAuth.ACL_DELIMITER.join(acl))
        url = "http://{0}{1}?{2}={3}".format(AT_HOSTNAME, '/q_escape_ignore', atd.token_name, token)
        response = requests.get(url)
        self.assertEqual(404, response.status_code)

        url = "http://{0}{1}?{2}={3}".format(AT_HOSTNAME, '/q_escape_ignore/world/', atd.token_name, token)
        response = requests.get(url)
        self.assertEqual(404, response.status_code)
    ##########

    def test_times(self):
        if not (sys.version_info[0] == 2 and sys.version_info[1] <= 6):
            att = EdgeAuth(key=AT_ENCRYPTION_KEY, window_seconds=DEFAULT_WINDOW_SECONDS, escape_early=False)
            # start_time
            with self.assertRaises(EdgeAuthError):
                att.generateToken(start_time=-1)
            
            with self.assertRaises(EdgeAuthError):
                att.generateToken(start_time="hello")
            
            # end_time
            with self.assertRaises(EdgeAuthError):
                att.generateToken(end_time=-1)

            with self.assertRaises(EdgeAuthError):
                att.generateToken(end_time="hello")
            
            # window_seconds
            with self.assertRaises(EdgeAuthError):
                att.generateToken(window_seconds=-1)

            with self.assertRaises(EdgeAuthError):
                att.generateToken(window_seconds="hello")
    

if __name__ == '__main__':
    unittest.main()