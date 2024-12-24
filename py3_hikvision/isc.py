#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
import base64
import hashlib
import hmac
import uuid
from datetime import datetime

import py3_requests
from addict import Dict
from jsonschema.validators import Draft202012Validator
from requests import Response


class RequestUrl(py3_requests.RequestUrl):
    pass


class ValidatorJsonSchema(py3_requests.ValidatorJsonSchema):
    SUCCESS = Dict({
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
    })


class ResponseHandler(py3_requests.ResponseHandler):
    @staticmethod
    def success(response: Response = None):
        json_addict = ResponseHandler.status_code_200_json_addict(response=response)
        if Draft202012Validator(ValidatorJsonSchema.SUCCESS).is_valid(instance=json_addict):
            return json_addict.get("data", None)
        return None


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
        self.host = host[:-1] if host.endswith("/") else host
        self.ak = ak
        self.sk = sk

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
            method: str = py3_requests.RequestMethod.POST,
            path: str = "",
            headers: dict = {}
    ):
        method = method if isinstance(method, str) else py3_requests.RequestMethod.POST
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
            **kwargs
    ):
        """
        request with signature
        @see https://open.hikvision.com/docs/docId?productId=5c67f1e2f05948198c909700&version=%2Ff95e951cefc54578b523d1738f65f0a1
        :param kwargs:
        :return:
        """
        kwargs = Dict(kwargs)
        kwargs.setdefault("method", py3_requests.RequestMethod.POST)
        kwargs.setdefault("response_handler", ResponseHandler.success)
        kwargs.setdefault("url", "")
        kwargs.setdefault("headers", Dict())
        url = kwargs.get("url", "")
        if not url.startswith("/artemis"):
            if not url.startswith("/"):
                url = f"/artemis/{url}"
            else:
                url = f"/artemis{url}"
        kwargs["url"] = url
        kwargs["headers"] = self.headers(
            method=kwargs.get("method", py3_requests.RequestMethod.POST),
            path=kwargs.get("url", ""),
            headers=kwargs.get("headers", Dict())
        )
        return py3_requests.request(**kwargs.to_dict())
