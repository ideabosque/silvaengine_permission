#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from datetime import datetime
from silvaengine_utility import Utility
from silvaengine_resource import ResourceModel
from .models import RelationshipModel, RoleModel
from .enumerations import RoleRelationshipType, RoleType
import uuid, pendulum, jsonpickle


# Create role
def create_role_handler(channel, kwargs):
    try:
        role_id = str(uuid.uuid1())
        now = datetime.utcnow()
        permissions = _get_unvisible_permissions(
            channel=channel,
            permissions=kwargs.get("permissions", []),
        )
        # resources = {}
        # results = Utility.json_loads(
        #     Utility.json_dumps(
        #         [
        #             resource
        #             for resource in ResourceModel.scan(
        #                 filter_condition=ResourceModel.apply_to == str(channel).strip()
        #             )
        #         ]
        #     )
        # )

        # for resource in results:
        #     operations = []

        #     for operation, items in resource.get("operations", {}).items():
        #         for item in items:
        #             if item.get("visible") == False:
        #                 operations.append(
        #                     {
        #                         "operation_name": item.get("action"),
        #                         "operation": str(operation).strip(),
        #                         "exclude": [],
        #                     }
        #                 )

        #     if len(operations):
        #         resources[resource.get("resource_id")] = operations

        # for rule in permissions:
        #     if rule.get("resource_id") and resources.get(rule.get("resource_id")):
        #         rule["permissions"] += resources.get(rule.get("resource_id"))
        #         resources.pop(rule.get("resource_id"))

        # if len(resources):
        #     for resource_id, items in resources.items():
        #         permissions.append(
        #             {
        #                 "resource_id": resource_id,
        #                 "permissions": items,
        #             }
        #         )

        RoleModel(
            role_id,
            **{
                "name": kwargs.get("name"),
                "type": int(kwargs.get("role_type", 0)),
                "apply_to": str(channel).strip(),
                "is_admin": bool(kwargs.get("is_admin", True)),
                # "permissions": kwargs.get("permissions", []),
                "permissions": permissions,
                "description": kwargs.get("role_description"),
                "status": bool(kwargs.get("status", True)),
                "updated_by": kwargs.get("updated_by"),
                "created_at": now,
                "updated_at": now,
            },
        ).save()

        return RoleModel.get(role_id, None)
    except Exception as e:
        raise e


# Update role for specified ID.
def update_role_handler(channel, kwargs):
    try:
        role = RoleModel(kwargs.get("role_id"))
        actions = [
            RoleModel.updated_at.set(datetime.utcnow()),
        ]
        rules = {
            "name": "name",
            "is_admin": "is_admin",
            "role_type": "type",
            "role_description": "description",
            "permissions": "permissions",
            "status": "status",
            "updated_by": "updated_by",
        }

        for argument, field in rules.items():
            if kwargs.get(argument) is not None:
                value = kwargs.get(argument)

                if argument in ["permissions"]:
                    value = _get_unvisible_permissions(
                        channel=channel,
                        permissions=kwargs.get("permissions", []),
                    )

                actions.append(getattr(RoleModel, field).set(value))

        condition = (RoleModel.role_id == kwargs.get("role_id")) & (
            RoleModel.apply_to == str(channel).strip()
        )

        role.update(
            actions=actions,
            condition=condition,
        )

        return RoleModel.get(kwargs.get("role_id"), None)
    except Exception as e:
        raise e


# Delete role by specified ID.
def delete_role_handler(channel, role_id):
    try:
        if role_id is None or str(role_id).strip() == "":
            raise Exception("`roleId` is required", 400)

        condition = (RoleModel.role_id == role_id) & (
            RoleModel.apply_to == str(channel).strip()
        )

        # Delete the role record.
        return RoleModel(role_id).delete(condition=condition)
    except Exception as e:
        raise e


# Create relationship of role / group / user.
def create_relationship_handler(channel, operator_id, kwargs):
    try:
        relationship_id = str(uuid.uuid1())
        now = datetime.utcnow()
        filter_conditions = (
            # (RelationshipModel.apply_to == str(channel).strip())
            # &
            (RelationshipModel.user_id == str(kwargs.get("user_id")).strip())
            & (RelationshipModel.role_id == str(kwargs.get("role_id")).strip())
            & (RelationshipModel.group_id == str(kwargs.get("group_id")).strip())
        )
        relationship_ids = list(
            set(
                [
                    str(item.relationship_id).strip()
                    # for item in RelationshipModel.scan(
                    for item in RelationshipModel.apply_to_type_index.query(
                        hash_key=str(channel).strip(),
                        range_key_condition=(
                            (
                                RelationshipModel.type
                                == int(kwargs.get("relationship_type", 0))
                            )
                        ),
                        filter_condition=filter_conditions,
                    )
                ]
            )
        )

        if len(relationship_ids):
            actions = [
                RelationshipModel.updated_at.set(now),
                RelationshipModel.updated_by.set(
                    str(
                        kwargs.get(
                            "updated_by",
                            operator_id if operator_id else "setup",
                        )
                    ).strip()
                ),
            ]
            rules = {
                "relationship_type": {"field": "type", "type": "int"},
                "user_id": {"field": "user_id", "type": "str"},
                "role_id": {"field": "role_id", "type": "str"},
                "group_id": {"field": "group_id", "type": "str"},
                "status": {"field": "status", "type": "bool"},
            }

            for argument, rule in rules.items():
                if kwargs.get(argument) is not None and hasattr(
                    RelationshipModel, rule.get("field")
                ):
                    value = kwargs.get(argument)

                    if rule.get("type") == "int":
                        value = int(value)
                    elif rule.get("type") == "str":
                        value = str(value).strip()
                    elif rule.get("type") == "bool":
                        value = bool(value)

                    actions.append(
                        getattr(RelationshipModel, rule.get("field")).set(value)
                    )

            for id in relationship_ids:
                RelationshipModel(id).update(
                    actions=actions,
                    condition=(
                        RelationshipModel.relationship_id.is_in(*relationship_ids)
                    )
                    & (RelationshipModel.apply_to == str(channel).strip()),
                )

            relationship_id = relationship_ids[0]
        else:
            RelationshipModel(
                relationship_id,
                **{
                    "type": int(kwargs.get("relationship_type", 0)),
                    "apply_to": str(channel).strip(),
                    "user_id": str(kwargs.get("user_id")).strip(),
                    "role_id": str(kwargs.get("role_id")).strip(),
                    "group_id": str(kwargs.get("group_id")).strip(),
                    "created_at": now,
                    "updated_at": now,
                    "updated_by": str(
                        kwargs.get(
                            "updated_by",
                            operator_id if operator_id else "setup",
                        )
                    ).strip(),
                    "status": bool(kwargs.get("status", True)),
                },
            ).save()
        return RelationshipModel.get(relationship_id)
    except Exception as e:
        raise e


# Update relationship for specified ID.
def update_relationship_handler(channel, kwargs):
    try:
        relationship = RelationshipModel(kwargs.get("relationship_id"))
        actions = [
            RelationshipModel.updated_at.set(datetime.utcnow()),
        ]
        fields = {
            "relationship_type": "type",
            "user_id": "user_id",
            "role_id": "role_id",
            "group_id": "group_id",
            "is_admin": "is_admin",
            "updated_by": "updated_by",
            "status": "status",
        }
        need_update = False

        for argument, field in fields.items():
            if kwargs.get(argument) is not None:
                need_update = True

                actions.append(
                    getattr(RelationshipModel, field).set(kwargs.get(argument))
                )

        if need_update:
            condition = (
                RelationshipModel.relationship_id == kwargs.get("relationship_id")
            ) & (RelationshipModel.apply_to == str(channel).strip())

            relationship.update(
                actions=actions,
                condition=condition,
            )

        return RelationshipModel.get(kwargs.get("relationship_id"))
    except Exception as e:
        raise e


# Delete relationship by specified ID.
def delete_relationship_handler(channel, relationship_id):
    try:
        if relationship_id is None or str(relationship_id).strip() == "":
            raise Exception("`relationshipId` is required", 400)

        # Delete the group/user/role relationship.
        return RelationshipModel(relationship_id).delete()
    except Exception as e:
        raise e


# Bulk save relationships
def save_relationships_handler(channel, operator_id, relationships):
    try:
        if (
            relationships is None
            or type(relationships) is not list
            or len(relationships) < 1
        ):
            raise Exception("`relationships` is required", 400)

        now = datetime.utcnow()

        for relationship in relationships:
            if (
                relationship.get("type") is None
                or not relationship.get("user_id")
                or not relationship.get("role_id")
                or (
                    int(relationship.get("type", 0)) != 0
                    and not relationship.get("group_id")
                )
            ):
                raise Exception("Bad reqeust", 400)

            filter_conditions = (
                RelationshipModel.user_id == str(relationship.get("user_id")).strip()
            )

            if int(relationship.get("type", 0)) != 0 and relationship.get("group_id"):
                filter_conditions = filter_conditions & (
                    RelationshipModel.group_id
                    == str(relationship.get("group_id")).strip()
                )

            for item in RelationshipModel.apply_to_type_index.query(
                hash_key=str(channel).strip(),
                range_key_condition=(
                    RelationshipModel.type == int(relationship.get("type", 0))
                ),
                filter_condition=filter_conditions,
            ):
                delete_relationship_handler(
                    channel=channel,
                    relationship_id=str(item.relationship_id).strip(),
                )

        for relationship in relationships:
            RelationshipModel(
                str(uuid.uuid1()),
                **{
                    "type": int(relationship.get("type", 0)),
                    "apply_to": str(channel).strip(),
                    "user_id": str(relationship.get("user_id")).strip(),
                    "role_id": str(relationship.get("role_id")).strip(),
                    "group_id": str(relationship.get("group_id")).strip(),
                    "created_at": now,
                    "updated_at": now,
                    "updated_by": str(
                        relationship.get(
                            "updated_by",
                            operator_id if operator_id else "setup",
                        )
                    ).strip(),
                    "status": bool(relationship.get("status", True)),
                },
            ).save()

    except Exception as e:
        raise e


def get_roles(user_id, channel, is_admin, group_id):
    try:
        if not user_id:
            raise Exception("Invalid user ID.", 403)
        elif not channel:
            raise Exception("Unrecognized request origin", 401)

        # Check user's permissions
        filter_conditions = RelationshipModel.user_id == str(user_id).strip()

        if not is_admin and group_id:
            filter_conditions = (filter_conditions) & (
                RelationshipModel.group_id == group_id
            )

        role_ids = list(
            set(
                [
                    str(relationship.role_id).strip()
                    for relationship in RelationshipModel.apply_to_type_index.query(
                        hash_key=str(channel).strip(),
                        filter_condition=filter_conditions,
                    )
                ]
            )
        )

        if len(role_ids) < 1:
            raise Exception("The current user is not assigned any role", 403)

        return Utility.json_dumps(
            [
                role
                for role in RoleModel.scan(
                    RoleModel.role_id.is_in(*list(set(role_ids)))
                )
            ]
        )
    except Exception as e:
        raise e


# Get a list of resource permissions for a specified user
def get_user_permissions(authorizer, channel, group_id=None):
    try:
        if not authorizer or not channel:
            raise Exception("Missing required parameter(s)")

        # cognito_user_sub = authorizer.get("sub")
        user_id = str(authorizer.get("user_id")).strip()

        if not user_id:
            return None

        # Query user / group / role relationships
        filter_conditions = RelationshipModel.user_id == user_id

        if group_id:
            filter_conditions = (filter_conditions) & (
                RelationshipModel.group_id == str(group_id).strip()
            )

        role_ids = [
            relationship.role_id
            for relationship in RelationshipModel.apply_to_type_index.query(
                hash_key=str(channel).strip(),
                filter_condition=filter_conditions,
            )
        ]

        if len(role_ids) < 1:
            return None

        rules = []
        result = {}

        for role in RoleModel.scan(
            (RoleModel.role_id.is_in(*list(set(role_ids))))
            & (RoleModel.apply_to == str(channel).strip())
        ):
            rules += role.permissions

        resources = {}
        resource_ids = list(set([str(rule.resource_id).strip() for rule in rules]))

        if len(resource_ids) < 1:
            return None

        for resource in ResourceModel.scan(
            (ResourceModel.resource_id.is_in(*resource_ids))
            & (ResourceModel.apply_to == str(channel).strip())
        ):
            resources[resource.resource_id] = resource

        for rule in rules:
            resource_id = rule.resource_id.strip()
            resource = resources.get(resource_id)

            if (
                not resource_id
                or not hasattr(resource, "function")
                or not hasattr(resource, "operations")
            ):
                continue

            function_name = getattr(resource, "function")

            if not result.get(function_name):
                result[function_name] = []

            if type(rule.permissions):
                for permission in rule.permissions:
                    if permission.operation and permission.operation_name:
                        result[function_name].append(
                            str(permission.operation_name).strip().lower()
                        )

            result[function_name] = list(set(result[function_name]))

        return result
    except Exception as e:
        raise e


def check_permission(roles, resource) -> bool:
    if (
        not resource.get("operation")
        or not resource.get("operation_name")
        or not resource.get("fields")
    ):
        return False

    permissions = []

    for role in roles:
        if (
            not role.permissions
            or not role.role_id
            or type(role.permissions) is not list
            or len(role.permissions) < 1
        ):
            continue

        permissions += role.permissions

    rules = []

    for permission in permissions:
        if (
            not permission.permissions
            or not permission.resource_id
            or type(permission.permissions) is not list
            or len(permission.permissions) < 1
        ):
            continue

        rules += permission.permissions

    m = {}
    request_operation = resource.get("operation").strip().lower()
    request_operation_name = resource.get("operation_name").strip().lower()
    request_fields = resource.get("fields")

    for rule in rules:
        if (
            not rule.operation
            or not rule.operation_name
            or request_operation != rule.operation.strip().lower()
        ):
            continue

        operation_name = rule.operation_name.strip().lower()

        if not m.get(operation_name):
            m[operation_name] = []

        if type(rule.exclude) is list and len(rule.exclude):
            m[operation_name] = list(set(m[operation_name] + rule.exclude))

    if type(m.get(request_operation_name)) is list:
        for field in m.get(request_operation_name):
            path, field = field.strip().lower().split(":", 2)

            if (
                path
                and field
                and path != ""
                and field != ""
                and request_fields.get(path)
                and field.strip().lower() in request_fields.get(path)
            ):
                return False

        return True

    return False


# Obtain user roles according to the specified user ID
def get_roles_by_user_id(
    user_id,
    relationship_type,
    channel,
    group_id=None,
    ignore_permissions=True,
):
    # 1. If user or relationship type is empty
    if not user_id or relationship_type is None or not channel:
        return []

    arguments = {
        "limit": None,
        "hash_key": str(channel).strip(),
        "range_key_condition": (RelationshipModel.type == int(relationship_type)),
        # "filter_condition": (RelationshipModel.type == int(relationship_type)),
        # & (RelationshipModel.apply_to == str(channel).strip()),
    }
    filter_conditions = []

    if type(user_id) is list and len(user_id):
        # arguments["filter_condition"] = arguments["filter_condition"] & (
        #     RelationshipModel.user_id.is_in(*list(set(user_id)))
        # )
        filter_conditions.append(RelationshipModel.user_id.is_in(*list(set(user_id))))
    else:
        # arguments["filter_condition"] = arguments["filter_condition"] & (
        #     RelationshipModel.user_id == str(user_id).strip()
        # )
        filter_conditions.append(RelationshipModel.user_id == str(user_id).strip())

    if group_id and str(group_id).strip() != "":
        # arguments["filter_condition"] = arguments["filter_condition"] & (
        #     RelationshipModel.group_id == str(group_id).strip()
        # )
        filter_conditions.append(RelationshipModel.group_id == str(group_id).strip())

    if len(filter_conditions):
        arguments["filter_condition"] = filter_conditions.pop(0)

        for index, condition in enumerate(filter_conditions):
            if index < 1:
                arguments["filter_condition"] = (arguments["filter_condition"]) & (
                    condition
                )
            else:
                arguments["filter_condition"] = arguments["filter_condition"] & (
                    condition
                )

    # 2. Get role ids.
    role_ids = []
    relationships = []

    # for relationship in RelationshipModel.scan(**arguments):
    for relationship in RelationshipModel.apply_to_type_index.query(**arguments):
        relationships.append(relationship)

        if relationship.role_id and str(relationship.role_id).strip() not in role_ids:
            role_ids.append(str(relationship.role_id).strip())

    # 3. Get roles
    roles = {}

    if len(role_ids):
        # @TODO: If role_ids more than 100, will be failure.
        role_ids = list(set(role_ids))

        for ids in [role_ids[i : i + 90] for i in range(0, len(role_ids), 90)]:
            for role in RoleModel.scan(
                (RoleModel.role_id.is_in(*ids))
                & (RoleModel.apply_to == str(channel).strip())
            ):
                # role = Utility.json_loads(
                #     Utility.json_dumps(role.__dict__["attribute_values"])
                # )

                # if role.get("permissions") and ignore_permissions:
                #     del role["permissions"]
                # if ignore_permissions:
                #     setattr(role, "permissions", None)

                # if role.get("role_id") and role.get("name"):
                #     roles[role.get("role_id")] = {
                #         "name": role.get("name"),
                #         "id": role.get("role_id"),
                #         "type": role.get("type"),
                #     }

                if role.role_id and role.name:
                    roles[role.role_id] = {
                        "name": role.name,
                        "id": role.role_id,
                        "type": role.type,
                    }

    # 4. Get user roles.
    user_roles = {}

    for relationship in relationships:
        if relationship.role_id:
            rid = str(relationship.role_id).strip()
            uid = str(relationship.user_id).strip()
            gid = (
                str(relationship.group_id).strip()
                if relationship.group_id
                and str(relationship.group_id).strip().lower() != "none"
                else str(RoleType.NORMAL.name).strip().lower()
            )

            # if not rid in role_ids:
            #     role_ids.append(rid)

            if not user_roles.get(uid):
                user_roles[uid] = {}

            if not user_roles.get(uid, {}).get(gid):
                user_roles[uid][gid] = {
                    "relationship_type": relationship.type,
                    "roles": [roles.get(rid)] if roles.get(rid) else [],
                    "group_id": gid,
                }
            elif roles.get(rid):
                user_roles[uid][gid]["roles"].append(roles.get(rid))

        # for uid, group in user_roles.items():
        #     for gid, value in group.items():
        #         user_roles[uid][gid] = {
        #             "group_id": gid,
        #             "relationship_type": value.get("type"),
        #             "roles": [
        #                 roles.get(rid)
        #                 for rid in list(set(value.get("role_ids")))
        #                 if roles.get(rid)
        #             ],
        #         }

    if type(user_id) is not list and user_roles.get(str(user_id).strip()):
        return user_roles.get(str(user_id).strip()).values()

    return user_roles


# Obtain user roles according to the specified user ID
# relationship_type: 0 - team, 1 - seller
def get_users_by_role_type(
    role_types,
    channel,
    settings,
    relationship_type=0,
    group_ids=None,
) -> list:
    t = lambda: int(pendulum.now().timestamp() * 1000)
    s = t()
    f = s
    print(">>>>>>>>>>>>>>> START: {}".format(s))

    if (
        (type(role_types) is not list and len(role_types))
        or not channel
        or not settings
    ):
        return []

    # 1. Get callback function.
    fn_get_users = Utility.import_dynamically(
        "user_engine",
        "get_users_by_ids",
        "UserEngine",
        {"logger": None, **settings},
    )

    if not callable(fn_get_users):
        raise Exception("Module is not exists or the function is uncallable", 500)

    print(">>>>>>>>>>>>>>> Get callback function: {}".format(t() - s))
    s = t()

    # 2. Get roles
    role_types = list(set([int(role_type) for role_type in role_types]))

    if type(group_ids) is list and len(group_ids):
        group_ids = list(set([str(group_id).strip() for group_id in group_ids]))

    role_filter_condition = (
        (RoleModel.is_admin == True)
        & (RoleModel.apply_to == str(channel).strip())
        & (RoleModel.status == True)
        & (RoleModel.type.is_in(*role_types))
    )
    # roles = Utility.json_loads(
    #     Utility.json_dumps(
    #         {
    #             role.role_id: role
    #             for role in RoleModel.scan(filter_condition=role_filter_condition)
    #         }
    #     )
    # )
    roles = {
        role.role_id: role
        for role in RoleModel.scan(filter_condition=role_filter_condition)
    }

    if not len(roles):
        raise Exception("No roles", 500)

    print(">>>>>>>>>>>>>>> Get roles: {}".format(t() - s))
    s = t()

    # 3. Get relationships & user ids.
    relationship_filter_condition = (
        RelationshipModel.role_id.is_in(*list(set(roles.keys())))
        # & (RelationshipModel.type == int(relationship_type))
        # & (RelationshipModel.apply_to == str(channel).strip())
    )
    # relationships = Utility.json_loads(
    #     Utility.json_dumps(
    #         [
    #             relationship
    #             for relationship in RelationshipModel.scan(
    #                 filter_condition=relationship_filter_condition
    #             )
    #         ]
    #     )
    # )
    # relationships = [
    #     # orjson.loads(
    #     #     orjson.dumps(
    #     #         relationship, option=orjson.OPT_NAIVE_UTC | orjson.OPT_SERIALIZE_NUMPY
    #     #     )
    #     # )
    #     Utility.convert_object_to_dict(relationship)
    #     for relationship in RelationshipModel.apply_to_type_index.query(
    #         hash_key=str(channel).strip(),
    #         range_key_condition=(RelationshipModel.type == int(relationship_type)),
    #         filter_condition=relationship_filter_condition,
    #     )
    # ]
    relationships = RelationshipModel.apply_to_type_index.query(
        hash_key=str(channel).strip(),
        range_key_condition=(RelationshipModel.type == int(relationship_type)),
        filter_condition=relationship_filter_condition,
    )
    print(">>>>>>>>>>>>>>> Get relationships 11111111111: {}".format(t() - s))
    s = t()
    # relationships = Utility.json_loads(Utility.json_dumps(test))

    print(">>>>>>>>>>>>>>> Get relationships: {}".format(t() - s))
    s = t()

    user_ids = [relationship.user_id for relationship in relationships]
    users = {}

    if len(user_ids):
        users = fn_get_users(user_ids=list(set(user_ids)), settings=settings)

    print(">>>>>>>>>>>>>>> Get users: {}".format(t() - s))
    s = t()

    # 4. User relations
    role_users = {}

    for relationship in relationships:
        if (
            type(group_ids) is list
            and len(group_ids)
            and relationship.group_id
            and not str(relationship.group_id).strip() in group_ids
        ):
            continue

        user_id = str(relationship.user_id).strip()
        role_id = str(relationship.role_id).strip()
        group_id = str(relationship.group_id).strip()

        if user_id and users.get(user_id):
            setattr(relationship, "user_base_info", users.get(user_id))
            # relationship["user_base_info"] = users.get(user_id)

        if role_id and not role_users.get(role_id):
            role_users.update({role_id: {}})

        if group_id:
            if not role_users.get(role_id).get(group_id):
                role_users[role_id].update({group_id: []})

            role_users[role_id][group_id].append(relationship)

    print(">>>>>>>>>>>>>>> Get user relationships: {}".format(t() - s))
    s = t()

    # 5. Result
    results = []

    for role_id, role in roles.items():
        # if role.get("permissions"):
        #     # role.permissions = []
        #     del role["permissions"]
        # if role.get("permissions"):
        # role.permissions = []
        # del role["permissions"]
        setattr(role, "permissions", None)

        if role_users.get(str(role_id).strip()):
            # role.update({"groups": role_users.get(str(role_id).strip())})
            # role["groups"] = role_users.get(str(role_id).strip())
            setattr(role, "groups", role_users.get(str(role_id).strip()))
            results.append(role)

    print(">>>>>>>>>>>>>>> Result: {}".format(t() - s))
    s = t()

    results = jsonpickle.decode(jsonpickle.encode(results, unpicklable=True))

    print(">>>>>>>>>>>>>>> Format result: {}".format(t() - s))

    print(results)

    print(">>>>>>>>>>>>>>> Total spent: {}".format(t() - f))

    return results


def get_roles_by_type(types, channel, status=None, is_admin=None) -> dict:
    try:
        roles = {}

        if type(types) is list and len(types) and channel:
            types = list(set([int(role_type) for role_type in types]))
            filter_condition = (RoleModel.type.is_in(*types)) & (
                RoleModel.apply_to == str(channel).strip()
            )

            if type(status) is bool:
                filter_condition = filter_condition & (RoleModel.status == status)

            if type(is_admin) is bool:
                filter_condition = filter_condition & (RoleModel.is_admin == is_admin)

            for role in RoleModel.scan(filter_condition=filter_condition):
                if type(roles.get(role.type)) is not list:
                    roles[role.type] = []

                roles[role.type].append(role)

        return roles
    except Exception as e:
        raise e


# Delete user roles by conditions.
def delete_relationships_by_condition(
    relationship_type,
    channel,
    role_ids=None,
    group_ids=None,
    user_ids=None,
):
    try:
        if role_ids and type(role_ids) is not list:
            role_ids = [str(role_ids).strip()]

        if relationship_type is None or not channel:
            raise Exception("Missing required parameters", 400)
        elif (
            (
                type(group_ids) is list
                and len(group_ids) > 99
                and RoleRelationshipType.ADMINISTRATOR.value != relationship_type
            )
            or (type(role_ids) is list and len(role_ids) > 99)
            or (type(user_ids) is list and len(user_ids) > 99)
        ):
            raise Exception(
                "The number of batch query operations must be less than 100", 400
            )

        filter_conditions = [
            RelationshipModel.type == int(relationship_type),
            RelationshipModel.apply_to == str(channel).strip(),
        ]

        if type(group_ids) is list and len(group_ids):
            group_ids = list(set([str(group_id).strip() for group_id in group_ids]))

            filter_conditions.append(RelationshipModel.group_id.is_in(*group_ids))

        if type(role_ids) is list and len(role_ids):
            role_ids = list(set([str(role_id).strip() for role_id in role_ids]))

            filter_conditions.append(RelationshipModel.role_id.is_in(*role_ids))

        if type(user_ids) is list and len(user_ids):
            user_ids = list(set([str(user_id).strip() for user_id in user_ids]))

            filter_conditions.append(RelationshipModel.user_id.is_in(*user_ids))

        filter_condition = None

        if len(filter_conditions):
            filter_condition = filter_conditions.pop(0)

            for condition in filter_conditions:
                filter_condition = filter_condition & (condition)

        for relationship in RelationshipModel.scan(filter_condition=filter_condition):
            relationship.delete()

        return True
    except Exception as e:
        print(type(e), e)
        raise e


# Check user permissions.
def check_user_permissions(
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
    logger=None,
):
    try:
        if (
            not channel
            or not settings
            or not module_name
            or not class_name
            or not function_name
            or not operation
            or not operation_type
            or not user_id
            or not group_id
            or relationship_type is None
        ):
            return False

        get_users = Utility.import_dynamically(
            "user_engine",
            "get_users_by_ids",
            "UserEngine",
            {"logger": logger, **dict(settings)},
        )

        if not callable(get_users):
            raise Exception("Module is not exists or the function is uncallable", 500)

        users = get_users(user_ids=[str(user_id).strip()], settings=settings)

        if len(users) < 1:
            return False
        elif bool(int(users.get(str(user_id).strip(), {}).get("is_admin", 0))):
            return True

        ### 1. Check user & team relationship exists.
        filter_condition = (
            (RelationshipModel.user_id == str(user_id).strip())
            & (RelationshipModel.apply_to == str(channel).strip())
            & (RelationshipModel.group_id == str(group_id).strip())
            & (RelationshipModel.type == int(relationship_type))
        )
        role_ids = list(
            set(
                [
                    relationship.role_id
                    for relationship in RelationshipModel.scan(
                        filter_condition=filter_condition
                    )
                    if relationship.role_id
                ]
            )
        )

        if len(role_ids) < 1:
            return False

        #### 1.1. Get roles by role ids
        # @TODO: len(role_ids) must less than 99
        max_length = 90
        permissions = []

        for i in range(0, len(role_ids), max_length):
            filter_condition = (
                RoleModel.role_id.is_in(*role_ids[i : i + max_length])
            ) & (RoleModel.apply_to == str(channel).strip())

            for role in RoleModel.scan(filter_condition=filter_condition):
                if (
                    role.permissions
                    and type(role.permissions) is list
                    and len(role.permissions)
                ):
                    permissions += role.permissions

        if len(permissions) < 1:
            return False

        ### 2. Get resources.
        filter_condition = (
            (ResourceModel.module_name == str(module_name).strip())
            & (ResourceModel.apply_to == str(channel).strip())
            & (ResourceModel.class_name == str(class_name).strip())
            & (ResourceModel.function == str(function_name).strip())
        )
        resource_ids = list(
            set(
                [
                    str(resource.resource_id).strip()
                    for resource in ResourceModel.scan(
                        filter_condition=filter_condition
                    )
                    if resource.resource_id
                ]
            )
        )

        if len(resource_ids) < 1:
            return False

        operation_type = str(operation_type).strip()
        operation = str(operation).strip()

        for permission in permissions:
            if (
                not permission.resource_id
                or type(permission.permissions) is not list
                or len(permission.permissions) < 1
            ):
                continue

            if str(permission.resource_id).strip() in resource_ids:
                for p in permission.permissions:
                    if p.operation == operation_type and p.operation_name == operation:
                        return True

        return False
    except Exception as e:
        raise e


def _get_unvisible_permissions(channel, permissions):
    resources = {}
    results = Utility.json_loads(
        Utility.json_dumps(
            [
                resource
                for resource in ResourceModel.scan(
                    filter_condition=ResourceModel.apply_to == str(channel).strip()
                )
            ]
        )
    )

    for resource in results:
        operations = []

        for operation, items in resource.get("operations", {}).items():
            for item in items:
                if item.get("visible") == False:
                    operations.append(
                        {
                            "operation_name": item.get("action"),
                            "operation": str(operation).strip(),
                            "exclude": [],
                        }
                    )

        if len(operations):
            resources[resource.get("resource_id")] = operations

    for rule in permissions:
        if rule.get("resource_id") and resources.get(rule.get("resource_id")):
            rule["permissions"] += resources.get(rule.get("resource_id"))
            resources.pop(rule.get("resource_id"))

    if len(resources):
        for resource_id, items in resources.items():
            permissions.append(
                {
                    "resource_id": resource_id,
                    "permissions": items,
                }
            )

    return permissions


def add_resource():
    with open("f:\install.log", "a") as fd:
        fd.write("Test\n")
