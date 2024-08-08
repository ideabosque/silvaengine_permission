#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pynamodb.models import Model
from pynamodb.attributes import (
    ListAttribute,
    MapAttribute,
    UnicodeAttribute,
    BooleanAttribute,
    UTCDateTimeAttribute,
    NumberAttribute,
)
from pynamodb.indexes import GlobalSecondaryIndex, AllProjection
import os

__author__ = "bl"

class ApplyToTypeIndex(GlobalSecondaryIndex):
    """
    This class represents a local secondary index
    """

    class Meta:
        billing_mode = "PAY_PER_REQUEST"
        # All attributes are projected
        projection = AllProjection()
        index_name = "apply_to-type-index"

    apply_to = UnicodeAttribute(hash_key=True)
    type = NumberAttribute(range_key=True)


class BaseModel(Model):
    class Meta:
        billing_mode = "PAY_PER_REQUEST"
        region = os.getenv("REGIONNAME")
        aws_access_key_id = os.getenv("aws_access_key_id")
        aws_secret_access_key = os.getenv("aws_secret_access_key")

        if region is None or aws_access_key_id is None or aws_secret_access_key is None:
            from dotenv import load_dotenv

            if load_dotenv():
                if region is None:
                    region = os.getenv("REGION_NAME")

                if aws_access_key_id is None:
                    aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")

                if aws_secret_access_key is None:
                    aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")


class TraitModel(BaseModel):
    class Meta(BaseModel.Meta):
        pass

    created_at = UTCDateTimeAttribute()
    updated_at = UTCDateTimeAttribute()
    updated_by = UnicodeAttribute()


class ResourceConstraintMap(MapAttribute):
    operation = UnicodeAttribute()
    operation_name = UnicodeAttribute()
    # [] = allowed all, ["field" ...] - Exclude specifed field(s)
    exclude = ListAttribute()
    # field = String()


class RoleConstraintMap(MapAttribute):
    resource_id = UnicodeAttribute()
    permissions = ListAttribute(of=ResourceConstraintMap)


class RoleModel(TraitModel):
    class Meta(TraitModel.Meta):
        table_name = "se-roles"

    apply_to_type_index = ApplyToTypeIndex()
    role_id = UnicodeAttribute(hash_key=True)
    apply_to = UnicodeAttribute()
    # type: 0 - Normal, 1 - GWI Account Manger, 2 - GWI QC Manager
    type = NumberAttribute(default=0)
    name = UnicodeAttribute()
    permissions = ListAttribute(of=RoleConstraintMap)
    description = UnicodeAttribute(null=True)
    is_admin = BooleanAttribute(default=False)
    status = BooleanAttribute(default=True)


class RelationshipModel(TraitModel):
    class Meta(TraitModel.Meta):
        table_name = "se-relationships"

    apply_to_type_index = ApplyToTypeIndex()
    relationship_id = UnicodeAttribute(hash_key=True)
    apply_to = UnicodeAttribute()
    # type: 0 - amdin, 1 - Seller, 2 - team
    type = NumberAttribute(default=0)
    user_id = UnicodeAttribute()
    role_id = UnicodeAttribute()
    group_id = UnicodeAttribute(null=True)
    status = BooleanAttribute(default=True)
    is_default = BooleanAttribute(null=True,default=False)
