#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from silvaengine_utility import JSON
from graphene import (
    ObjectType,
    InputObjectType,
    String,
    DateTime,
    List,
    Int,
    Boolean,
)


__author__ = "bl"


class ConstraintType(ObjectType):
    operation = String(required=True)
    operation_name = String(required=True)
    # [] = allowed all, ["field" ...] - Exclude specifed field(s)
    exclude = List(String)
    # field = String()


class ConstraintInputType(InputObjectType):
    operation = String(required=True)
    operation_name = String(required=True)
    # [] = allowed all, ["field" ...] - Exclude specifed field(s)
    exclude = List(String)
    # field = String()


class PermissionType(ObjectType):
    resource_id = String(required=True)
    permissions = List(ConstraintType, required=True)


class PermissionInputType(InputObjectType):
    resource_id = String()
    permissions = List(ConstraintInputType)


class RoleType(ObjectType):
    role_id = String()
    # type: 0 - Normal, 1 - GWI Accoumnt Manger, 2 - GWI QC Manager
    type = Int()
    name = String()
    apply_to = String()
    description = String()
    permissions = List(PermissionType)
    is_admin = Boolean()
    status = Boolean()
    updated_by = String()
    created_at = DateTime()
    updated_at = DateTime()


class RolesType(ObjectType):
    items = List(RoleType)
    page_size = Int()
    page_number = Int()
    total = Int()
    # last_evaluated_key = JSON()


class RelationshipType(ObjectType):
    relationship_id = String()
    # type: 0 - amdin, 1 - Seller, 2 - team
    type = Int()
    group_id = String()
    user_id = String()
    role_id = String()
    apply_to = String()
    created_at = DateTime()
    updated_at = DateTime()
    updated_by = String()
    status = Boolean()
    is_default =Boolean()


class UserRelationshipType(ObjectType):
    relationship_id = String()
    group_id = String()
    user_id = String()
    # type: 0 - amdin, 1 - Seller, 2 - team
    type = Int()
    apply_to = String()
    user = JSON()
    role_id = String()
    created_at = DateTime()
    updated_at = DateTime()
    updated_by = String()
    status = Boolean()
    is_default =Boolean()


class SimilarUserType(RoleType):
    users = List(JSON)


class SimilarUsersType(ObjectType):
    items = List(SimilarUserType)
    page_size = Int()
    page_number = Int()
    total = Int()


class RelationshipsType(ObjectType):
    items = List(RelationshipType)
    page_size = Int()
    page_number = Int()
    total = Int()
    # last_evaluated_key = JSON()


class UserRelationshipsType(ObjectType):
    items = List(UserRelationshipType)
    page_size = Int()
    page_number = Int()
    total = Int()
    # last_evaluated_key = JSON()


class CertificateType(ObjectType):
    access_token = String()
    id_token = String()
    refresh_token = String()
    expires_in = Int()
    token_type = String()
    permissions = JSON()
    context = JSON()


class RelationshipInputType(InputObjectType):
    # type: 0 - amdin, 1 - Seller, 2 - team
    type = Int(required=True)
    group_id = String(required=True)
    user_id = String(required=True)
    role_id = String(required=True)
    updated_by = String()
    status = Boolean()
    is_default = Boolean()


class RoleDetectionType(ObjectType):
    roles = JSON()
