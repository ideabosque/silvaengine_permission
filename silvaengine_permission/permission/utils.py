#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bl"


def validate_required(fields, input):
    try:
        fields = list(set(list(fields)))

        if len(fields) and not input:
            raise Exception("Missing required parameter(s)", 400)

        for field in fields:
            if input and input.get(field) is None:
                raise Exception(f"Parameter `{field}` is required", 400)
    except Exception as e:
        raise e


def is_admin_user(context):
    try:
        return bool(
            int(
                str(
                    context.get("context", {}).get("authorizer", {}).get("is_admin")
                ).strip()
            )
        )
    except Exception as e:
        raise e


def get_seller_id(context):
    try:
        seller_id = context.get("context", {}).get("authorizer", {}).get("seller_id")

        if is_admin_user(context):
            return None
        elif not seller_id:
            raise Exception("Missing seller id", 400)

        return str(seller_id).strip()
    except Exception as e:
        raise e
