#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
import base64
import hashlib
import hmac
import uuid
from datetime import datetime

import py3_requests
import requests
from addict import Dict
from jsonschema.validators import Draft202012Validator
from requests import Response


class RequestUrl:
    pass


class ValidatorJsonSchema:
    """
    json schema settings
    """
    NORMAL_SCHEMA = {
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
    }


class ResponseHandler:
    """
    response handler
    """

    @staticmethod
    def normal_handler(response: Response = None):
        if isinstance(response, Response) and response.status_code == 200:
            json_addict = Dict(response.json())
            if Draft202012Validator(ValidatorJsonSchema.NORMAL_SCHEMA).is_valid(instance=json_addict):
                return json_addict.get("data", Dict())
            return None
        raise Exception(f"Response Handler Error {response.status_code}|{response.text}")


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
        self.host = host
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
            **kwargs
    ):
        """
        request with signature
        @see https://open.hikvision.com/docs/docId?productId=5c67f1e2f05948198c909700&version=%2Ff95e951cefc54578b523d1738f65f0a1
        :param kwargs:
        :return:
        """
        kwargs = Dict(kwargs)
        kwargs.setdefault("method", "POST")
        kwargs.setdefault("response_handler", ResponseHandler.normal_handler)
        kwargs.setdefault("url", "")
        kwargs.setdefault("headers", Dict())
        kwargs["headers"] = self.headers(
            method=kwargs.get("method", "POST"),
            path=kwargs.get("url", ""),
            headers=kwargs.get("headers", Dict())
        )
        return py3_requests.request(**kwargs.to_dict())
