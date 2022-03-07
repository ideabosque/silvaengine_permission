#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function


__author__ = "bl"

from graphene import Schema
from hashlib import md5
from silvaengine_utility import Utility
from .permission.schema import (
    RoleQuery,
    RoleMutations,
    role_type_class,
)
from .permission.handlers import (
    get_roles,
    get_user_permissions,
    get_roles_by_user_id,
    get_users_by_role_type,
    create_relationship_handler,
    get_roles_by_type,
    delete_relationships_by_condition,
    check_user_permissions,
)
from .permission.enumerations import RoleRelationshipType

# Hook function applied to deployment
def deploy() -> list:
    return [
        {
            "service": "permissions",
            "class": "Permission",
            "functions": {
                "role_graphql": {
                    "is_static": True,
                    "label": "Permissions",
                    "mutation": [
                        {
                            "action": "createRole",
                            "label": "Create Role",
                        },
                        {
                            "action": "createRelationship",
                            "label": "Create relationship",
                        },
                        {
                            "action": "updateRole",
                            "label": "Modify Role",
                        },
                        {
                            "action": "updateRelationship",
                            "label": "Update relationship",
                        },
                        {
                            "action": "saveRelationships",
                            "label": "Bulk save relationships",
                        },
                        {
                            "action": "deleteRole",
                            "label": "Delete Role",
                        },
                        {
                            "action": "deleteRelationship",
                            "label": "Delete relationship",
                        },
                    ],
                    "query": [
                        {
                            "action": "roles",
                            "label": "View Roles",
                        },
                        {
                            "action": "role",
                            "label": "View Role",
                        },
                        {
                            "action": "users",
                            "label": "Query Permission Relationships",
                        },
                        {
                            "action": "detection",
                            "label": "Role uniqueness detection",
                        },
                    ],
                    "type": "RequestResponse",
                    "support_methods": ["POST"],
                    "is_auth_required": True,
                    "is_graphql": True,
                    "settings": "beta_core_api",
                },
                "permission_check_callback": {
                    "is_static": False,
                    "label": "Permission Check Callback",
                    "mutation": [],
                    "query": [],
                    "type": "RequestResponse",
                    "support_methods": ["POST", "GET"],
                    "is_auth_required": False,
                    "is_graphql": False,
                    "disabled_in_resources": True,
                    "settings": "beta_core_api",
                },
            },
        }
    ]


class Permission(object):
    def __init__(self, logger, **setting):
        self.logger = logger
        self.setting = setting

    # Role interface by graphql
    def role_graphql(self, **params):
        try:
            apply_to = params.get("endpoint_id")

            if not apply_to:
                raise Exception("Unrecognized request origin", 401)

            schema = Schema(
                query=RoleQuery,
                mutation=RoleMutations,
                types=role_type_class(),
            )
            context = {
                "logger": self.logger,
                "setting": self.setting,
                "context": params.get("context"),
                "apply_to": str(apply_to).strip(),
            }
            variables = params.get("variables", {})
            operations = params.get("query")
            response = {
                "errors": "Invalid operations.",
                "status_code": 400,
            }

            if not operations:
                return Utility.json_dumps(response)

            execution_result = schema.execute(
                operations, context_value=context, variable_values=variables
            )

            if not execution_result:
                response = {
                    "errors": "Invalid execution result.",
                }
            elif execution_result.errors:
                response = {
                    "errors": [
                        Utility.format_error(e) for e in execution_result.errors
                    ],
                }
            elif execution_result.invalid:
                response = execution_result
            elif execution_result.data:
                response = {"data": execution_result.data, "status_code": 200}
            else:
                response = {
                    "errors": "Uncaught execution error.",
                }

            return Utility.json_dumps(response)
        except Exception as e:
            raise e

    # Implementation of hook configuration `permission_check_hooks`.
    def permission_check_callback(self, **params):
        return get_roles(
            user_id=params.get("user_id"),
            channel=params.get("channel"),
            is_admin=params.get("is_admin"),
            group_id=params.get("group_id"),
        )

    def get_user_permissions(self, authorizer, channel):
        return get_user_permissions(authorizer=authorizer, channel=channel)

    # Get roles
    def get_roles_by_user_id(
        self,
        channel,
        user_id,
        relationship_type,
        group_id=None,
        ignore_permissions=True,
    ):
        try:
            return get_roles_by_user_id(
                channel=channel,
                user_id=user_id,
                relationship_type=relationship_type,
                group_id=group_id,
                ignore_permissions=ignore_permissions,
            )
        except Exception as e:
            raise e

    # Get users
    def get_users_by_role_type(
        self, channel, settings, role_types, relationship_type=0, ids=None
    ) -> list:
        try:
            return get_users_by_role_type(
                channel=channel,
                settings=settings,
                role_types=role_types,
                relationship_type=relationship_type,
                group_ids=ids,
            )
        except Exception as e:
            raise e

    # Save role relationships
    def save_role_relationship(
        self,
        channel,
        role_type,
        relationship_type,
        group_ids,
        user_ids,
        updated_by=None,
        by_group_id=False,
    ):
        try:
            operator_id = str(updated_by).strip() if updated_by else "0"
            # 1. Get roles by role type
            roles = get_roles_by_type(types=[role_type], channel=str(channel).strip())

            # 2. save relationship.
            if type(roles.get(role_type)) is list and type(user_ids) is list:
                for role in roles.get(role_type):
                    kwargs = {
                        "channel": str(channel).strip(),
                        "role_ids": [role.role_id],
                        "relationship_type": relationship_type,
                        "user_ids": user_ids,
                        "group_ids": list(set(group_ids))
                        if type(group_ids) is list
                        else [str(group_ids).strip()],
                    }

                    if by_group_id:
                        del kwargs["user_ids"]
                    else:
                        del kwargs["group_ids"]

                    delete_relationships_by_condition(**kwargs)

                    if len(user_ids):
                        for user_id in list(set(user_ids)):
                            kwargs = {
                                "role_id": role.role_id,
                                "relationship_type": relationship_type,
                                "user_id": user_id,
                                "updated_by": updated_by,
                                "status": True,
                            }

                            if type(group_ids) is list:
                                if len(group_ids):
                                    for group_id in list(set(group_ids)):
                                        if str(group_id).strip() != "":
                                            kwargs["group_id"] = str(group_id).strip()

                                            create_relationship_handler(
                                                channel=str(channel).strip(),
                                                operator_id=operator_id,
                                                **kwargs,
                                            )
                            else:
                                kwargs["group_id"] = str(group_ids).strip()

                                create_relationship_handler(
                                    channel=str(channel).strip(),
                                    operator_id=operator_id,
                                    **kwargs,
                                )

        except Exception as e:
            raise e

    # Assign users to role.
    def assign_roles_to_users(
        self,
        channel,
        role_users_map,
        relationship_type,
        updated_by,
        group_id=None,
        is_remove_existed=True,
    ):
        try:
            if type(role_users_map) is dict and len(role_users_map):
                operator_id = str(updated_by).strip() if updated_by else "0"
                group_ids = None

                if (
                    relationship_type != RoleRelationshipType.ADMINISTRATOR.value
                    and group_id
                ):
                    group_ids = group_id if type(group_id) is list else [group_id]

                if is_remove_existed:
                    user_ids = list(
                        set(
                            [
                                str(user_id).strip()
                                for items in role_users_map.values()
                                for user_id in items
                            ]
                        )
                    )

                    delete_relationships_by_condition(
                        channel=str(channel).strip(),
                        relationship_type=relationship_type,
                        group_ids=group_ids,
                        user_ids=user_ids,
                    )

                for role_id, user_ids in role_users_map.items():
                    for user_id in user_ids:
                        kwargs = {
                            "role_id": str(role_id).strip(),
                            "relationship_type": relationship_type,
                            "user_id": user_id,
                            "updated_by": updated_by,
                            "status": True,
                        }

                        if group_ids is not None:
                            for group_id in list(set(group_ids)):
                                kwargs["group_id"] = group_id

                                create_relationship_handler(
                                    channel=str(channel).strip(),
                                    operator_id=operator_id,
                                    **kwargs,
                                )
                        else:
                            create_relationship_handler(
                                channel=str(channel).strip(),
                                operator_id=operator_id,
                                **kwargs,
                            )
        except Exception as e:
            raise e

    # Remove user's role
    def remove_roles_from_users(
        self, channel, relationship_type, user_ids=None, group_ids=None, role_ids=None
    ):
        try:
            delete_relationships_by_condition(
                channel=str(channel).strip(),
                relationship_type=relationship_type,
                group_ids=group_ids,
                user_ids=user_ids,
                role_ids=role_ids,
            )

        except Exception as e:
            raise e

    # Check user permissions.
    def check_user_permissions(
        self,
        channel,
        settings,
        module_name,
        class_name,
        function_name,
        operation_type,
        operation,
        relationship_type,
        user_id,
        group_id,
    ):
        try:
            return check_user_permissions(
                channel=str(channel).strip(),
                settings=settings,
                module_name=module_name,
                class_name=class_name,
                function_name=function_name,
                operation_type=operation_type,
                operation=operation,
                relationship_type=relationship_type,
                user_id=user_id,
                group_id=group_id,
            )

        except Exception as e:
            raise e

    # Get roles
    def get_roles_by_specific_user(
        self,
        channel,
        user_id,
        relationship_type,
        group_id=None,
        ignore_permissions=True,
    ):
        try:
            roles = get_roles_by_user_id(
                channel=channel,
                user_id=user_id,
                relationship_type=relationship_type,
                group_id=group_id,
                ignore_permissions=ignore_permissions,
            )

            if len(roles):
                return roles

            return None
        except Exception as e:
            raise e
