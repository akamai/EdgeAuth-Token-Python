# -*- coding: utf-8 -*-

import os
import sys
import unittest

sys.path.append("akamai/edgeauth")
sys.path.append("../akamai/edgeauth")
from edgeauth import EdgeAuth, EdgeAuthError

import requests
from requests.utils import quote


if 'TEST_MODE' in os.environ and os.environ['TEST_MODE'] == 'TRAVIS':
    ET_HOSTNAME = os.environ['ET_HOSTNAME']
    ET_ENCRYPTION_KEY = os.environ['ET_ENCRYPTION_KEY']
    ET_TRANSITION_KEY = os.environ['ET_TRANSITION_KEY']
    ET_SALT = os.environ['ET_SALT']
else:
    import secrets
    ET_HOSTNAME = secrets.ET_HOSTNAME
    ET_ENCRYPTION_KEY = secrets.ET_ENCRYPTION_KEY
    ET_TRANSITION_KEY = secrets.ET_TRANSITION_KEY    
    ET_SALT = secrets.ET_SALT

DEFAULT_WINDOW_SECONDS = 500


class TestEdgeAuth(unittest.TestCase):

    def setUp(self):
        # Test for Query String
        self.at = EdgeAuth(**{'key': ET_ENCRYPTION_KEY, 'window_seconds': DEFAULT_WINDOW_SECONDS})
        
        # Test for Cookie
        self.cat = EdgeAuth(key=ET_ENCRYPTION_KEY, algorithm='sha1', window_seconds=DEFAULT_WINDOW_SECONDS)

        # Test for Header
        self.hat = EdgeAuth(key=ET_ENCRYPTION_KEY, algorithm='md5', window_seconds=DEFAULT_WINDOW_SECONDS)

    def _token_setting(self, ttype, escape_early, transition, payload, session_id):
        t = None
        if ttype == 'q':
            t = self.at
        elif ttype == 'c':
            t = self.cat
        elif ttype == 'h':
            t = self.hat
        
        if transition:
            t.key = ET_TRANSITION_KEY

        t.payload = payload
        t.session_id = session_id
        t.escape_early = escape_early
        
    def _queryAssertEqual(self, path, auth_path, expacted, escape_early=False, transition=False,
                          payload=None, session_id=None, is_url=True):
        self._token_setting('q', escape_early, transition, payload, session_id)
                
        if is_url:
            token = self.at.generate_url_token(auth_path)
        else:
            token = self.at.generate_acl_token(auth_path)
 
        url = "http://{0}{1}{4}{2}={3}".format(ET_HOSTNAME, path, self.at.token_name, token,
            '&' if '?' in path else '?')
        response = requests.get(url)
        self.assertEqual(expacted, response.status_code)
    
    def _cookieAssertEqual(self, path, auth_path, expacted, escape_early=False, transition=False,
                           payload=None, session_id=None, is_url=True):
        self._token_setting('c', escape_early, transition, payload, session_id)
        if is_url:
            token = self.cat.generate_url_token(auth_path)
        else:
            token = self.cat.generate_acl_token(auth_path)

        url = "http://{0}{1}".format(ET_HOSTNAME, path)
        response = requests.get(url, cookies={self.cat.token_name: token})
        self.assertEqual(expacted, response.status_code)

    def _headerAssertEqual(self, path, auth_path, expacted, escape_early=False, transition=False,
                           payload=None, session_id=None, is_url=True):
        self._token_setting('h', escape_early, transition, payload, session_id)
        if is_url:
            token = self.hat.generate_url_token(auth_path)
        else:
            token = self.hat.generate_acl_token(auth_path)

        url = "http://{0}{1}".format(ET_HOSTNAME, path)
        response = requests.get(url, headers={self.hat.token_name: token})
        self.assertEqual(expacted, response.status_code)

    def _test_case_set(self, query_path, query_auth_path,
                             cookie_path, cookie_auth_path,
                             header_path, header_auth_path,
                             escape_early, is_url):
        # General Test
        self._queryAssertEqual(query_path, query_auth_path, 404, escape_early=escape_early, is_url=is_url)
        self._cookieAssertEqual(cookie_path, cookie_auth_path, 404, escape_early=escape_early, is_url=is_url)
        self._headerAssertEqual(header_path, header_auth_path, 404, escape_early=escape_early, is_url=is_url)

        # Transition Key Test
        self._queryAssertEqual(query_path, query_auth_path, 404, transition=True, escape_early=escape_early, is_url=is_url)
        self._cookieAssertEqual(cookie_path, cookie_auth_path, 404, transition=True, escape_early=escape_early, is_url=is_url)
        self._headerAssertEqual(header_path, header_auth_path, 404, transition=True, escape_early=escape_early, is_url=is_url)

        # Payload Test
        self._queryAssertEqual(query_path, query_auth_path, 404, payload='SOME_PAYLOAD_DATA', escape_early=escape_early, is_url=is_url)
        self._cookieAssertEqual(cookie_path, cookie_auth_path, 404, payload='SOME_PAYLOAD_DATA', escape_early=escape_early, is_url=is_url)
        self._headerAssertEqual(header_path, header_auth_path, 404, payload='SOME_PAYLOAD_DATA', escape_early=escape_early, is_url=is_url)

        # Session Id Test
        self._queryAssertEqual(query_path, query_auth_path, 404, session_id='SOME_SESSION_ID_DATA', escape_early=escape_early, is_url=is_url)
        self._cookieAssertEqual(cookie_path, cookie_auth_path, 404, session_id='SOME_SESSION_ID_DATA', escape_early=escape_early, is_url=is_url)
        self._headerAssertEqual(header_path, header_auth_path, 404, session_id='SOME_SESSION_ID_DATA', escape_early=escape_early, is_url=is_url)
    
    ##########
    # URL TEST
    ##########
    def test_url_escape_on__ignoreQuery_yes(self):
        self._test_case_set("/q_escape_ignore?hello=world", "/q_escape_ignore", 
                            "/c_escape_ignore", "/c_escape_ignore", 
                            "/h_escape_ignore", "/h_escape_ignore", 
                            escape_early=True, is_url=True)

    def test_url_escape_off__ignoreQuery_yes(self):
        self._test_case_set("/q_ignore", "/q_ignore", 
                            "/c_ignore?1=2", "/c_ignore", 
                            "/h_ignore", "/h_ignore",
                            escape_early=False, is_url=True)

    def test_url_escape_on__ignoreQuery_no(self):
        query_path = "/q_escape"
        cookie_path = "/c_escape"
        header_path = "/h_escape"

        self._test_case_set(query_path, query_path, 
                            cookie_path, cookie_path, 
                            header_path, header_path, 
                            escape_early=True, is_url=True)

        query_path = "/q_escape?" + quote("안녕=세상") 
        cookie_path = "/c_escape?" + quote("hello=world")
        header_path = "/h_escape?" + quote("1=2")
        self._test_case_set(query_path, query_path, 
                            cookie_path, cookie_path, 
                            header_path, header_path, 
                            escape_early=True, is_url=True)

    def test_url_escape_off__ignoreQuery_no(self):
        query_path = "/q"
        cookie_path = "/c"
        header_path = "/h"
        self._test_case_set(query_path, query_path, 
                            cookie_path, cookie_path, 
                            header_path, header_path, 
                            escape_early=False, is_url=True)

        query_path = "/q" + quote("1=2")
        cookie_path = "/c" + quote("안녕=세상")
        header_path = "/h" + quote("hello=world")
        self._test_case_set(query_path, query_path, 
                            cookie_path, cookie_path, 
                            header_path, header_path, 
                            escape_early=False, is_url=True)
   
    def test_url_query_escape_on__ignore_yes_with_salt(self):
        query_salt_path = "/salt"
        ats = EdgeAuth(key=ET_ENCRYPTION_KEY, salt=ET_SALT, window_seconds=DEFAULT_WINDOW_SECONDS, escape_early=True)
        token = ats.generate_url_token(query_salt_path)
        url = "http://{0}{1}?{2}={3}".format(ET_HOSTNAME, query_salt_path, ats.token_name, token)
        response = requests.get(url)
        self.assertEqual(404, response.status_code)
    ##########
    
    ##########
    # ACL TEST
    ##########
    def test_acl_escape_on__ignoreQuery_yes(self):
        self._test_case_set("/q_escape_ignore/안녕", "/q_escape_ignore/*",
                            "/c_escape_ignore/", "/c_escape_ignore/*",
                            "/h_escape_ignore/hello", "/h_escape_ignore/*",
                            escape_early=False, is_url=False)

    def test_acl_escape_off__ignoreQuery_yes(self):
        self._test_case_set("/q_ignore/world", "/q_ignore/??r??",
                            "/c_ignore/a", "/c_ignore/?", 
                            "/h_ignore/112", "/h_ignore/??*", 
                            escape_early=False, is_url=False)

    def test_acl_escape_on__ignoreQuery_no(self):
        self._test_case_set("/q_escape/" + quote("안"), "/q_escape/?????????", 
                            "/c_escape/a/b/c/d", "/c_escape/*",
                            "/h_escape/1/2", "/h_escape/*",
                            escape_early=False, is_url=False)

    def test_acl_escape_off__ignoreQuery_no(self):
        self._test_case_set("/q/abc", "/q/???", 
                            "/c/세상/안녕", "/c/*",
                            "/h", "/h",
                            escape_early=False, is_url=False)
    
    def test_acl_asta_escape_on__ignoreQuery_yes(self):
        ata = EdgeAuth(key=ET_ENCRYPTION_KEY, window_seconds=DEFAULT_WINDOW_SECONDS, escape_early=False)
        token = ata.generate_acl_token('/q_escape_ignore/*')
        url = "http://{0}{1}?{2}={3}".format(ET_HOSTNAME, '/q_escape_ignore/hello', ata.token_name, token)
        response = requests.get(url)
        self.assertEqual(404, response.status_code)
    
    def test_acl_deli_escape_on__ignoreQuery_yes(self):
        atd = EdgeAuth(key=ET_ENCRYPTION_KEY, window_seconds=DEFAULT_WINDOW_SECONDS, escape_early=False)
        acl = ['/q_escape_ignore', '/q_escape_ignore/*']
        token = atd.generate_acl_token(acl)
        url = "http://{0}{1}?{2}={3}".format(ET_HOSTNAME, '/q_escape_ignore', atd.token_name, token)
        response = requests.get(url)
        self.assertEqual(404, response.status_code)

        url = "http://{0}{1}?{2}={3}".format(ET_HOSTNAME, '/q_escape_ignore/world/', atd.token_name, token)
        response = requests.get(url)
        self.assertEqual(404, response.status_code)
    ##########

    def test_times(self):
        if not (sys.version_info[0] == 2 and sys.version_info[1] <= 6):
            att = EdgeAuth(key=ET_ENCRYPTION_KEY, window_seconds=DEFAULT_WINDOW_SECONDS, escape_early=False)
            
            self.assertEqual(None, att.start_time)
            self.assertEqual(None, att.end_time)

            # start_time
            with self.assertRaises(EdgeAuthError):
                att.start_time=-1
                att.generate_url_token("/")
            
            with self.assertRaises(EdgeAuthError):
                att.start_time="hello"
                att.generate_url_token("/")
            
            # end_time
            with self.assertRaises(EdgeAuthError):
                att.end_time=-1
                att.generate_url_token("/")

            with self.assertRaises(EdgeAuthError):
                att.end_time="hello"
                att.generate_url_token("/")
            
            # window_seconds
            with self.assertRaises(EdgeAuthError):
                att.window_seconds=-1
                att.generate_url_token("/")

            with self.assertRaises(EdgeAuthError):
                att.window_seconds="hello"
                att.generate_url_token("/")


if __name__ == '__main__':
    unittest.main()