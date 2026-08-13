#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import json
import base64
import requests
import urllib3

logger = logging.getLogger(__name__)

class TimeoutHTTPAdapter(requests.adapters.HTTPAdapter):
    """A custom transport adapter that injects a default timeout."""
    # timeout suggested by AI, so that cron processes don't end up stacking up if a request fails
    # based on this https://byteful.com/blog/python-requests-timeout-techniques-for-stability
    def __init__(self, timeout=5, *args, **kwargs):
        self.timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)

class NR7101Exception(Exception):
    def __init__(self, error):
        self.error = error


class NR7101:
    def __init__(self, url, username, password, oid, params={}):
        self.url = url
        self.params = params
        password_b64 = base64.b64encode(password.encode("utf-8")).decode("utf-8")
        self.login_params = {
            "Input_Account": username,
            "Input_Passwd": password_b64,
            "currLang": "en",
            "RememberPassword": 0,
            "SHA512_password": False,
        }
        self.sessionkey = None
        self.oid = oid #for oid option
        # self.session to wrap the Timeout adapter.
        self.session = requests.Session()
        # timeouts set in the tuple (3.5,10) on the next line
        timeout_adapter = TimeoutHTTPAdapter(timeout=(3.5,10))
        self.session.mount("http://", timeout_adapter)
        self.session.mount("https://", timeout_adapter)

        # NR7101 is using by default self-signed certificates, so ignore the warnings
        self.params["verify"] = False
        urllib3.disable_warnings()

    def load_cookies(self, cookiefile):
        cookies = {}
        try:
            with open(cookiefile, "rt") as f:
                cookies = json.load(f)
            logger.debug("Cookies loaded")
            self.params["cookies"] = cookies
        except FileNotFoundError:
            logger.debug("Cookie file does not exist, ignoring.")
        except json.JSONDecodeError:
            logger.warning("Ignoring invalid cookie file.")

    def clear_cookies(self):
        self.params.pop("cookies", None)

    def store_cookies(self, cookiefile):
        try:
            cookies = self.params["cookies"]
        except KeyError:
            logger.warning("No cookie to write")
            return

        with open(cookiefile, "wt") as f:
            json.dump(cookies, f)
        logger.debug("Cookies saved")

    def login(self):
        login_json = json.dumps(self.login_params)

        with self.session.post(
            self.url + "/UserLogin", data=login_json, **self.params
        ) as r:
            if r.status_code != 200:
                logger.error("Unauthorized")
                return

            # Update cookies
            self.params["cookies"] = requests.utils.dict_from_cookiejar(r.cookies)
            self.sessionkey = r.json()["sessionkey"]
            return self.sessionkey

    def logout(self, sessionkey=None):
        if sessionkey is None:
            sessionkey = self.sessionkey
        with self.session.get(
            f"{self.url}/cgi-bin/UserLogout?sessionkey={sessionkey}", **self.params
        ) as r:
            assert r.status_code == 200

    def connect(self):
        with self.session.get(self.url + "/getBasicInformation", **self.params) as r:
            assert r.status_code == 200
            assert r.json()["result"] == "ZCFG_SUCCESS", "Connection failure"

        # Check login
        with self.session.get(self.url + "/UserLoginCheck", **self.params) as r:
            assert r.status_code == 200

#    def get_status(self, retries=2, oid_list):
    def get_status(self, retries=2):
        def parse_traffic_object(obj):
            ret = {}
            for iface, iface_st in zip(obj["ipIface"], obj["ipIfaceSt"]):
                ret[iface["X_ZYXEL_IfName"]] = iface_st
            return ret

        while retries > 0:
            try:
                if ( self.oid ):
                   # --oid OID 
                   logger.debug("Using --oid option") 
                   oid_result = self.get_json_object( self.oid )
                   return {
                       self.oid: oid_result,
                   }
                else:
                   # Default behaviour 
                   print("use cellwan_status, Traffic_Status") 
                   cellular = self.get_json_object("cellwan_status")
                   traffic = parse_traffic_object(self.get_json_object("Traffic_Status"))
                   return {
                    "cellular": cellular,
                    "traffic": traffic,
                   }
            except requests.exceptions.Timeout as e:
                logger.warning(f"Router connection timed out: {e}")
                # Burn a retry attempt and let the loop try again (or exit if retries run out)
                retries -= 1
            except requests.exceptions.HTTPError as e:
                logger.warning("HTTPError: {e}")
                if e.response.status_code == 401:
                    # Unauthorized
                    logger.info("Login")
                    self.login()
                elif e.response.status_code == 500:
                    logger.info(
                        "Internal server error received. Retrying without cookies."
                    )
                    self.clear_cookies()
                retries -= 1
        return None

    def get_json_object(self, oid):
        with self.session.get(self.url + "/cgi-bin/DAL?oid=" + oid, **self.params) as r:
            r.raise_for_status()
            j = r.json()
            assert j["result"] == "ZCFG_SUCCESS"
            return j["Object"][0]

    # TODO: Could add option for custom path and query
    # and return either JSON or RAW data.

    def reboot(self):
        if self.sessionkey is None:
            self.login()

        logger.info("Rebooting...")
        with self.session.post(
            f"{self.url}/cgi-bin/Reboot?sessionkey={self.sessionkey}", **self.params
        ) as r:
            r.raise_for_status()
            j = r.json()
            assert j["result"] == "ZCFG_SUCCESS"
