#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from importlib.util import find_spec
from importlib import import_module
from silvaengine_utility import Utility
from .types import (
    RoleType as OutputRoleType,
    RolesType,
    UserRelationshipType,
    SimilarUserType,
    SimilarUsersType,
    RoleDetectionType,
)
from .models import RelationshipModel, RoleModel
from .enumerations import RoleType
from copy import deepcopy

# @TODO: Apply status check
def resolve_roles(info, **kwargs):
    try:
        arguments = {
            "hash_key": str(info.context.get("apply_to")).strip(),
            "limit": int(
                kwargs.get(
                    "page_size",
                    info.context.get("setting", {}).get("max_size_per_page", 10),
                )
            ),
            "last_evaluated_key": None,
            "filter_condition": None,
        }
        # total = 0

        # Build filter conditions.
        # @SEE: {"ARGUMENT_NAME": "FIELD_NAME_OF_DATABASE_TABLE", ...}
        mappings = {
            "is_admin": "is_admin",
            "name": "name",
            "role_description": "description",
            "role_type": "type",
            "status": "status",
        }
        filter_conditions = []

        # Get filter condition from arguments
        # @TODO: If there is an operation such as `is_in`, this method or mapping must be extended`
        for argument, field in mappings.items():
            if kwargs.get(argument) is None or not hasattr(RoleModel, field):
                continue

            if field == "name":
                filter_conditions.append(
                    (
                        getattr(RoleModel, field).contains(
                            str(kwargs.get(argument)).strip()
                        )
                    )
                )
            else:
                filter_conditions.append(
                    (getattr(RoleModel, field) == kwargs.get(argument))
                )

        if kwargs.get("user_ids") is list:
            role_ids = [
                str(relationship.role_id).strip()
                for relationship in RelationshipModel.apply_to_type_index.query(
                    hash_key=info.context.get("apply_to"),
                    filter_condition=(
                        RelationshipModel.role_id.is_in(
                            *list(set(kwargs.get("user_ids",[])))
                        )
                    )
                )
            ]

            if len(role_ids):
                filter_conditions.append((RoleModel.role_id.is_in(*role_ids)))

        if len(filter_conditions):
            arguments["filter_condition"] = filter_conditions.pop(0)

            for condition in filter_conditions:
                arguments["filter_condition"] = (
                    arguments.get("filter_condition") & condition
                )

        # Count total of roles
        # for _ in RoleModel.scan(filter_condition=arguments.get("filter_condition")):
        #     total += 1

        # Pagination.
        pagination_offset = 0
        page_number = kwargs.get("page_number", 1)

        if type(page_number) not in [str, int, float] or int(page_number) < 1:
            page_number = 1

        if arguments.get("limit", 0) > 0 and page_number > 1:
            pagination_offset = (page_number - 1) * int(arguments.get("limit",0))

        pagination_arguments = {
            "hash_key": str(info.context.get("apply_to")).strip(),
            "limit": pagination_offset if pagination_offset > 0 else None,
            "last_evaluated_key": None,
            "filter_condition": arguments.get("filter_condition"),
            "attributes_to_get": ["role_id"],
        }

        # Skip (int(kwargs.get("page_number", 0)) - 1) rows
        pagination_results = RoleModel.apply_to_type_index.query(**pagination_arguments)
        # Discard the results of the iteration, and extract the cursor of the page offset from the iterator.
        _ = sum(1 for _ in pagination_results)
        # The iterator needs to be traversed first, and then the pagination cursor can be obtained through `last_evaluated_key` after the traversal is completed.
        if (
            not pagination_results.last_evaluated_key
            and pagination_results.total_count < pagination_offset
        ):
            return None
        
        arguments["last_evaluated_key"] = pagination_results.last_evaluated_key

        # if arguments.get("last_evaluated_key") is None:
        #     return None

        # Query role form database.
        results = RoleModel.apply_to_type_index.query(**arguments)
        roles = [
            OutputRoleType(
                # **Utility.json_loads(
                #     Utility.json_dumps(dict(**role.__dict__["attribute_values"]))
                # )
                **{
                    "role_id": role.role_id,
                    "type": role.type,
                    "name": role.name,
                    "apply_to": role.apply_to,
                    "description": role.description,
                    "permissions": role.permissions,
                    "is_admin": role.is_admin,
                    "status": role.status,
                    "updated_by": role.updated_by,
                    "created_at": role.created_at,
                    "updated_at": role.updated_at,
                }
            )
            for role in results
        ]

        if results.total_count < 1:
            return None

        return RolesType(
            items=roles,
            page_number=page_number,
            page_size=arguments.get("limit"),
            total=sum(1 for _ in RoleModel.apply_to_type_index.query(
                    hash_key= arguments.get("hash_key"),
                    filter_condition=arguments.get("filter_condition"),
                    attributes_to_get=["role_id"]
                )
            ),
        )
    except Exception as e:
        raise e


# @TODO: Apply status check
# Query users by relationship.
def resolve_users(info, **kwargs):
    try:
        arguments = {
            "hash_key": info.context.get("apply_to"),
            "limit": int(
                kwargs.get(
                    "page_size",
                    info.context.get("setting", {}).get("max_size_per_page", 10),
                )
            ),
            "last_evaluated_key": None,
            "filter_condition": None,
        }
        total = 0
        # Build filter conditions.
        # @SEE: {"ARGUMENT_NAME": "FIELD_NAME_OF_DATABASE_TABLE", ...}
        # Role model
        role_field_argument_mappings_eq = {
            "role_status": "status",
            "is_admin_role": "is_admin",
        }
        role_field_argument_mappings_in = {
            "role_type": "type",
            "role_name": "name",
            "role_id": "role_id",
        }
        role_filter_conditions = []

        # eq: Get filter condition from arguments for Roles
        for argument, field in role_field_argument_mappings_eq.items():
            if kwargs.get(argument) is None or not hasattr(RoleModel, field):
                continue

            role_filter_conditions.append(
                (getattr(RoleModel, field) == kwargs.get(argument))
            )

        # in: Get filter condition from arguments for Roles
        for argument, field in role_field_argument_mappings_in.items():
            if (
                not hasattr(RoleModel, field)
                or type(kwargs.get(argument)) is not list
                or len(kwargs.get(argument, [])) < 1
            ):
                continue

            role_filter_conditions.append(
                (getattr(RoleModel, field).is_in(*kwargs.get(argument)))
            )

        # Join the filter conditions
        if len(role_filter_conditions):
            arguments["filter_condition"] = role_filter_conditions.pop(0)

            for condition in role_filter_conditions:
                arguments["filter_condition"] = (
                    arguments["filter_condition"] & condition
                )

        # Pagination.
        if arguments.get("limit",0) > 0 and kwargs.get("page_number", 0) > 1:
            pagination_arguments = {
                "hash_key": info.context.get("apply_to"),
                "limit": (int(kwargs.get("page_number", 0)) - 1)
                * arguments.get("limit",0),
                "last_evaluated_key": None,
                "filter_condition": arguments["filter_condition"],
                "attributes_to_get": ["role_id"],
            }

            # Skip (int(kwargs.get("page_number", 0)) - 1) rows
            pagination_results = RoleModel.apply_to_type_index.query(**pagination_arguments)
            # Discard the results of the iteration, and extract the cursor of the page offset from the iterator.
            _ = sum(1 for _ in pagination_results)
            arguments["last_evaluated_key"] = pagination_results.last_evaluated_key

            if (
                arguments.get("last_evaluated_key") is None
                or pagination_results.total_count == total
            ):
                return None

        # Count total of roles
        roles = {}

        for role in RoleModel.apply_to_type_index.query(**arguments):
            if role:
                roles[role.role_id] = SimilarUserType(
                    users=[],
                    # **Utility.json_loads(
                    #     Utility.json_dumps(dict(**role.__dict__["attribute_values"]))
                    # )
                    **{
                        "role_id": role.role_id,
                        "type": role.type,
                        "name": role.name,
                        "apply_to": role.apply_to,
                        "description": role.description,
                        "permissions": role.permissions,
                        "is_admin": role.is_admin,
                        "status": role.status,
                        "updated_by": role.updated_by,
                        "created_at": role.created_at,
                        "updated_at": role.updated_at,
                    }
                )
                total += 1

        if (
            kwargs.get("role_id") and roles.get(kwargs.get("role_id")) is None
        ) or total == 0:
            return None

        relatinship_filter_conditions = [
            (RelationshipModel.role_id.is_in(*roles.keys())),
        ]
        # Relationship model
        relationship_field_argument_mappings_eq = {
            "relationship_status": "status",
            "relationship_type": "type",
            "relationship_is_default": "is_default",
        }
        relationship_field_argument_mappings_in = {
            "owner_id": "group_id",
        }

        # eq: Get filter condition from arguments
        for argument, field in relationship_field_argument_mappings_eq.items():
            if kwargs.get(argument) is None or not hasattr(RelationshipModel, field):
                continue

            relatinship_filter_conditions.append(
                (getattr(RelationshipModel, field) == kwargs.get(argument))
            )

        # in: Get filter condition from arguments
        for argument, field in relationship_field_argument_mappings_in.items():
            if (
                not hasattr(RelationshipModel, field)
                or type(kwargs.get(argument)) is not list
                or len(kwargs.get(argument, [])) < 1
            ):
                continue

            relatinship_filter_conditions.append(
                (getattr(RelationshipModel, field).is_in(*kwargs.get(argument)))
            )

        # Join the filter conditions
        filter_condition = None

        if len(relatinship_filter_conditions):
            filter_condition = relatinship_filter_conditions.pop(0)

            for condition in relatinship_filter_conditions:
                filter_condition = filter_condition & condition

        # Query data from the database.
        results = RelationshipModel.apply_to_type_index.query(
            hash_key=str(info.context.get("apply_to")).strip(),
            filter_condition=filter_condition,
        )
        relationships = [
            UserRelationshipType(
                **{
                    "relationship_id": relationship.relationship_id,
                    "group_id": relationship.group_id,
                    "user_id": relationship.user_id,
                    "type": relationship.type,
                    "apply_to": relationship.apply_to,
                    "role_id": relationship.role_id,
                    "created_at": relationship.created_at,
                    "updated_at": relationship.updated_at,
                    "updated_by": relationship.updated_by,
                    "status": relationship.status,
                    "is_default": relationship.is_default,
                }
                # **Utility.json_loads(
                #     Utility.json_dumps(
                #         dict(**relationship.__dict__["attribute_values"])
                #     )
                # )
            )
            for relationship in results
        ]

        if results.total_count < 1:
            return None

        fn = Utility.import_dynamically(
            module_name="user_engine",
            function_name="get_users_by_ids",
            class_name="UserEngine",
            constructor_parameters={
                "logger": info.context.get("logger"),
                **dict(info.context.get("setting", {})),
            },
        )

        if callable(fn):
            users = fn(
                user_ids=list(
                    set(
                        [
                            str(relationship.user_id).strip()
                            for relationship in relationships
                        ]
                    )
                ),
                settings=dict(info.context.get("setting", {})),
            )

            if len(users):
                for relationship in relationships:
                    user_ids = list(
                        set(
                            [
                                # user.cognito_user_sub
                                str(user["id"])
                                for user in roles[str(relationship.role_id).strip()].users
                                # if hasattr(user, "cognito_user_sub")
                                if ("id" in user)
                            ]
                        )
                    )

                    if (
                        relationship.role_id
                        and roles.get(str(relationship.role_id).strip())
                        and relationship.user_id
                        and users.get(str(relationship.user_id).strip())
                        and str(relationship.user_id).strip() not in user_ids
                    ):
                        users.get(str(relationship.user_id).strip()).update({
                            "is_default_manager": relationship.is_default if relationship.is_default else False,
                        })
                        # user = users.get(str(relationship.user_id).strip())
                        roles[str(relationship.role_id).strip()].users.append(deepcopy(users.get(str(relationship.user_id).strip())))

        return SimilarUsersType(
            items=roles.values(),
            page_number=kwargs.get("page_number", 1),
            page_size=arguments.get("limit"),
            total=total,
        )
    except Exception as e:
        raise e


# Query role info by specified ID.
def resolve_role(info, **kwargs):
    role = RoleModel.get(kwargs.get("role_id"))

    return OutputRoleType(
        **Utility.json_loads(Utility.json_dumps(role.__dict__["attribute_values"]))
    )


# Role uniqueness detection
def resolve_detection(info, **kwargs):
    role_name = str(kwargs.get("name", "")).strip()
    role_types = [
        RoleType.ACCOUNT_MANAGER.value,
        RoleType.QC_MANAGER.value,
        RoleType.DEPT_MANAGER.value,
    ]
    filter_conditions = (RoleModel.name == role_name)
    types = {
        t.value: {
            "type_alias": t.name,
            "is_exclusive": t.value != RoleType.NORMAL.value,
            "roles": [],
        }
        for t in RoleType
    }
    roles = {}

    for role in RoleModel.apply_to_type_index.query(
        hash_key=str(info.context.get("apply_to")).strip(),
        filter_condition=filter_conditions,
    ):
        role = role.__dict__["attribute_values"]

        if role.get("type") in role_types:
            if roles.get(role.get("type")) is None and types.get(role.get("type")):
                roles[role.get("type")] = types.get(role.get("type"))

            if (
                roles.get(role.get("type")) is not None
                and type(roles[role.get("type")].get("roles")) is list
            ):
                roles[role.get("type")]["roles"].append(
                    {
                        "name": role.get("name", ""),
                    }
                )

    return RoleDetectionType(roles=roles)
