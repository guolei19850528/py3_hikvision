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
    ARTEMIS_API_RESOURCE_V1_ORG_ORGLIST = "/artemis/api/resource/v1/org/orgList"
    ARTEMIS_API_RESOURCE_V1_ORG_ORGINDEXCODES_ORGINFO = "/artemis/api/resource/v1/org/orgIndexCodes/orgInfo"
    ARTEMIS_API_PMS_V1_CAR_CHARGE = "/artemis/api/pms/v1/car/charge"
    ARTEMIS_API_PMS_V1_CAR_CHARGE_DELETION = "/artemis/api/pms/v1/car/charge/deletion"
    ARTEMIS_API_PMS_V1_CAR_CHARGE_PAGE = "/artemis/api/pms/v1/car/charge/page"
    ARTEMIS_API_PMS_V1_TEMPCARINRECORDS_PAGE = "/artemis/api/pms/v1/tempCarInRecords/page"
    ARTEMIS_API_RESOURCE_V1_VEHICLE_BATCH_ADD = "/artemis/api/resource/v1/vehicle/batch/add"
    ARTEMIS_API_RESOURCE_V1_VEHICLE_SINGLE_UPDATE = "/artemis/api/resource/v1/vehicle/single/update"
    ARTEMIS_API_RESOURCE_V1_VEHICLE_BATCH_DELETE = "/artemis/api/resource/v1/vehicle/batch/delete"
    ARTEMIS_API_RESOURCE_V2_VEHICLE_ADVANCE_VEHICLELIST = "/artemis/api/resource/v2/vehicle/advance/vehicleList"
    ARTEMIS_API_RESOURCE_V2_PERSON_SINGLE_ADD = "/artemis/api/resource/v2/person/single/add"
    ARTEMIS_API_RESOURCE_V1_PERSON_SINGLE_UPDATE = "/artemis/api/resource/v1/person/single/update"
    ARTEMIS_API_RESOURCE_V1_PERSON_BATCH_DELETE = "/artemis/api/resource/v1/person/batch/delete"
    ARTEMIS_API_RESOURCE_V1_FACE_SINGLE_ADD = "/artemis/api/resource/v1/face/single/add"
    ARTEMIS_API_RESOURCE_V1_FACE_SINGLE_UPDATE = "/artemis/api/resource/v1/face/single/update"
    ARTEMIS_API_RESOURCE_V1_FACE_SINGLE_DELETE = "/artemis/api/resource/v1/face/single/delete"
    ARTEMIS_API_RESOURCE_V2_PERSON_ORGINDEXCODE_PERSONLIST = "/artemis/api/resource/v2/person/orgIndexCode/personList"
    ARTEMIS_API_RESOURCE_V2_PERSON_ADVANCE_PERSONLIST = "/artemis/api/resource/v2/person/advance/personList"
    ARTEMIS_API_RESOURCE_V1_PERSON_CONDITION_PERSONINFO = "/artemis/api/resource/v1/person/condition/personInfo"
    ARTEMIS_API_RESOURCE_V1_PERSON_PICTURE = "/artemis/api/resource/v1/person/picture"


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


class ISC(object):
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
        kwargs.setdefault("verify", False)
        kwargs.setdefault("headers", Dict())
        kwargs["headers"] = self.headers(
            method=kwargs.get("method", py3_requests.RequestMethod.POST),
            path=kwargs.get("url", ""),
            headers=kwargs.get("headers", Dict())
        )
        if not kwargs.get("url", "").startswith("http"):
            kwargs["url"] = self.host + kwargs["url"]
        return py3_requests.request(**kwargs.to_dict())
