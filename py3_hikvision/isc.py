#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
import base64
import hashlib
import hmac
import uuid
from datetime import datetime

import requests
from addict import Dict
from jsonschema.validators import Draft202012Validator
from requests import Response


class UrlSettings:
    pass


class Isc(object):
    """
    综合安防管理平台（iSecure Center）

    @see https://open.hikvision.com/docs/docId?productId=5c67f1e2f05948198c909700&version=%2Ff95e951cefc54578b523d1738f65f0a1
    """

    def __init__(
            self,
            host: str = "",
            ak: str = "",
            sk: str = "",
    ):
        """
         综合安防管理平台（iSecure Center）

        @see https://open.hikvision.com/docs/docId?productId=5c67f1e2f05948198c909700&version=%2Ff95e951cefc54578b523d1738f65f0a1
        :param host:
        :param ak:
        :param sk:
        """
        self.host = host if isinstance(host, str) else ""
        self.ak = ak if isinstance(ak, str) else ""
        self.sk = sk if isinstance(sk, str) else ""

    def _default_response_handler(self, response: Response = None):
        """
        default response handler
        :param response: requests.Response instance
        :return:
        """
        if isinstance(response, Response) and response.status_code == 200:
            json_addict = Dict(response.json())
            if Draft202012Validator({
                "type": "object",
                "properties": {
                    "code": {
                        "oneOf": [
                            {"type": "string", "const": "0"},
                            {"type": "integer", "const": 0},
                        ]
                    },
                },
                "required": ["code", "data"]
            }).is_valid(json_addict):
                return json_addict.data, response
        return False, response

    def timestamp(self):
        return int(datetime.now().timestamp() * 1000)

    def nonce(self):
        return uuid.uuid4().hex

    def signature(self, string: str = ""):
        return base64.b64encode(
            hmac.new(
                self.sk.encode(),
                string.encode(),
                digestmod=hashlib.sha256
            ).digest()
        ).decode()

    def headers(
            self,
            method: str = "POST",
            path: str = "",
            headers: dict = {}
    ):
        method = method if isinstance(method, str) else "POST"
        path = path if isinstance(path, str) else ""
        headers = headers if isinstance(headers, dict) else {}
        headers = {
            "accept": "*/*",
            "content-type": "application/json",
            "x-ca-signature-headers": "x-ca-key,x-ca-nonce,x-ca-timestamp",
            "x-ca-key": self.ak,
            "x-ca-nonce": self.nonce(),
            "x-ca-timestamp": str(self.timestamp()),
            **headers
        }
        string = "\n".join([
            method,
            headers["accept"],
            headers["content-type"],
            f"x-ca-key:{headers['x-ca-key']}",
            f"x-ca-nonce:{headers['x-ca-nonce']}",
            f"x-ca-timestamp:{headers['x-ca-timestamp']}",
            path,
        ])
        headers["x-ca-signature"] = self.signature(string=string)
        return headers

    def request_with_signature(
            self,
            method: str = "POST",
            path: str = None,
            **kwargs
    ):
        """
        request with signature

        @see https://open.hikvision.com/docs/docId?productId=5c67f1e2f05948198c909700&version=%2Ff95e951cefc54578b523d1738f65f0a1
        :param method:
        :param path:
        :param kwargs:
        :return:
        """
        method = method if isinstance(method, str) else "POST"
        path = path if isinstance(path, str) else ""
        if not path.startswith("/"):
            path = f"/{path}"
        headers = kwargs.pop("headers", {})
        kwargs["headers"] = self.headers(method=method, path=path, headers=headers)
        return requests.request(method=method, url=f"{self.host}{path}", **kwargs)
