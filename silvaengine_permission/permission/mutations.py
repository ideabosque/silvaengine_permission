#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from graphene import Field, Mutation, String, Boolean, Int, List
from silvaengine_utility import Utility
from .types import (
    RoleType,
    RelationshipType,
    PermissionInputType,
    RelationshipInputType,
)
from .handlers import (
    create_role_handler,
    update_role_handler,
    delete_role_handler,
    create_relationship_handler,
    update_relationship_handler,
    delete_relationship_handler,
    save_relationships_handler,
)
from .utils import notification
import traceback

# Append role info.
class CreateRole(Mutation):
    role = Field(RoleType)

    class Arguments:
        name = String(required=True)
        role_type = Int(required=True)
        is_admin = Boolean(required=True)
        role_description = String()
        permissions = List(PermissionInputType, required=True)
        updated_by = String()
        status = Boolean()

    @staticmethod
    def mutate(root, info, **kwargs):
        try:
            role = RoleType(
                **Utility.json_loads(
                    Utility.json_dumps(
                        create_role_handler(
                            channel=info.context.get("apply_to"), kwargs=kwargs
                        ).__dict__["attribute_values"]
                    )
                )
            )

            # Notification
            notification(info=info)
            return CreateRole(role=role)
        except Exception as e:
            info.context.get("logger").exception(traceback.format_exc())
            raise e


# Modify role info.
class UpdateRole(Mutation):
    role = Field(RoleType)

    class Arguments:
        role_id = String(required=True)
        name = String()
        role_type = Int()
        is_admin = Boolean()
        role_description = String()
        permissions = List(PermissionInputType)
        updated_by = String()
        status = Boolean()

    @staticmethod
    def mutate(root, info, **kwargs):
        try:
            role = RoleType(
                **Utility.json_loads(
                    Utility.json_dumps(
                        update_role_handler(
                            channel=info.context.get("apply_to"),
                            kwargs=kwargs,
                        ).__dict__["attribute_values"]
                    )
                )
            )

            # Notification
            notification(info=info)
            return UpdateRole(role=role)
        except Exception as e:
            info.context.get("logger").exception(traceback.format_exc())
            raise e


# Delete role
class DeleteRole(Mutation):
    ok = Boolean()

    class Arguments:
        role_id = String(required=True)

    @staticmethod
    def mutate(root, info, **kwargs):
        try:
            delete_role_handler(
                channel=info.context.get("apply_to"),
                role_id=kwargs.get("role_id"),
            )
            # Notification
            notification(info=info)
            return DeleteRole(ok=True)
        except Exception as e:
            info.context.get("logger").exception(traceback.format_exc())
            raise e


# Append role info.
class CreateRelationship(Mutation):
    relationship = Field(RelationshipType)

    class Arguments:
        group_id = String()
        relationship_type = Int(required=True)
        user_id = String(required=True)
        role_id = String(required=True)
        updated_by = String()
        status = Boolean()
        is_default = Boolean()

    @staticmethod
    def mutate(root, info, **kwargs):
        try:
            relationship = RelationshipType(
                **Utility.json_loads(
                    Utility.json_dumps(
                        create_relationship_handler(
                            channel=info.context.get("apply_to"),
                            operator_id=info.context.get("authorizer", {}).get(
                                "user_id", "setup"
                            ),
                            kwargs=kwargs,
                        ).__dict__["attribute_values"]
                    )
                )
            )
            # Notification
            notification(info=info)
            return CreateRelationship(relationship=relationship)
        except Exception as e:
            info.context.get("logger").exception(traceback.format_exc())
            raise e


# Modify role info.
class UpdateRelationship(Mutation):
    relationship = Field(RelationshipType)

    class Arguments:
        relationship_id = String(required=True)
        relationship_type = Int()
        group_id = String()
        user_id = String()
        role_id = String()
        updated_by = String()
        status = Boolean()
        is_default = Boolean()

    @staticmethod
    def mutate(root, info, **kwargs):
        try:
            relationship = RelationshipType(
                **Utility.json_loads(
                    Utility.json_dumps(
                        update_relationship_handler(
                            channel=info.context.get("apply_to"), kwargs=kwargs
                        ).__dict__["attribute_values"]
                    )
                )
            )

            # Notification
            notification(info=info)
            return UpdateRelationship(relationship=relationship)
        except Exception as e:
            info.context.get("logger").exception(traceback.format_exc())
            raise e


# Delete relationship
class DeleteRelationship(Mutation):
    ok = Boolean()

    class Arguments:
        relationship_id = String(required=True)

    @staticmethod
    def mutate(root, info, **kwargs):
        try:
            delete_relationship_handler(
                channel=info.context.get("apply_to"),
                relationship_id=kwargs.get("relationship_id"),
            )
            # Notification
            notification(info=info)
            return DeleteRelationship(ok=True)
        except Exception as e:
            info.context.get("logger").exception(traceback.format_exc())
            raise e


# Bulk save relationships
class SaveRelationships(Mutation):
    ok = Boolean()

    class Arguments:
        relationships = List(RelationshipInputType, required=True)

    @staticmethod
    def mutate(root, info, **kwargs):
        try:
            save_relationships_handler(
                channel=info.context.get("apply_to"),
                operator_id=info.context.get("authorizer", {}).get("user_id", "setup"),
                relationships=kwargs.get("relationships"),
            )
            # Notification
            notification(info=info)
            return SaveRelationships(ok=True)
        except Exception as e:
            info.context.get("logger").exception(traceback.format_exc())
            raise e
