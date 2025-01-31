#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""
=================================================
作者：[郭磊]
手机：[15210720528]
Email：[174000902@qq.com]
Github：https://github.com/guolei19850528/py3_hikvision
=================================================
"""

import setuptools
from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()
setup(
    name="py3-hikvision",
    version="1.0.0",
    description="The Python3 Hikvision Library Developed By Guolei",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/guolei19850528/py3_hikvision",
    author="guolei",
    author_email="174000902@qq.com",
    license="MIT",
    keywors=["hikvision", "海康威视", "人脸识别", "物业管理", "物管", "智慧社区", "智慧车场", "guolei", "郭磊"],
    packages=setuptools.find_packages('./'),
    install_requires=[
        "py3-requests",
        "addict",
        "retrying",
        "jsonschema",
        "diskcache",
        "redis",
        "setuptools",
        "wheel",
    ],
    python_requires='>=3.0',
    zip_safe=False
)
