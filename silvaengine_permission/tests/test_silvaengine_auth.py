#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bl"


from datetime import datetime, timedelta, date
from decimal import Decimal
from silvaengine_utility import Utility
from dotenv import load_dotenv
from os import path
import logging, sys, unittest, uuid, os

load_dotenv()
sys.path.insert(0, path.dirname(path.dirname(path.dirname(path.realpath(__file__)))))

from silvaengine_auth import Auth, RoleRelationshipType

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger()
setting = {
    "region_name": os.getenv("REGION_NAME"),
    "aws_access_key_id": os.getenv("AWS_ACCESS_KEY_ID"),
    "aws_secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
    "app_client_id": os.getenv("APP_CLIENT_ID"),
    "app_client_secret": os.getenv("APP_CLIENT_SECRET"),
    "custom_hooks": "relation_engine:RelationEngine:get_users_by_cognito_user_id",
}


class SilvaEngineAuthTest(unittest.TestCase):
    def setUp(self):
        self.auth = Auth(logger, **setting)
        logger.info("Initiate SilvaEngineAuthTest ...")

    def tearDown(self):
        logger.info("Destory SilvaEngineAuthTest ...")

    @unittest.skip("demonstrating skipping")
    def test_get_roles_graphql(self):
        query = """
            query roles(
                    $pageSize: Int
                    $pageNumber: Int
                    $isAdmin: Boolean
                    $status: Boolean
                    $description: String
                    $type: Int
                    $name: String
                ){
                roles(
                    pageSize: $pageSize
                    pageNumber: $pageNumber
                    isAdmin: $isAdmin
                    status: $status
                    roleDescription: $description
                    roleType: $type
                    name: $name
                ){
                    items {
                        roleId
                        name
                        permissions{
                            resourceId
                            permissions {
                                operation
                                operationName
                                exclude
                            }
                        }
                        description
                        isAdmin
                        status
                        type
                        createdAt
                        updatedAt
                        updatedBy
                    }
                    pageSize
                    pageNumber
                    total
                }
            }
        """
        variables = {
            "pageSize": 10,
            "pageNumber": 1,
            # "isAdmin": True,
            # "status": True,
            # "description": None,
            # "type": 0,
            # "name": None,
        }
        payload = {"query": query, "variables": variables}
        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_get_role_graphql(self):
        query = """
            query role( $roleId: String!){
                role (roleId: $roleId){
                    roleId
                    name
                    permissions{
                        resourceId
                        permissions {
                            operation
                            operationName
                            exclude
                        }
                    }
                    description
                    isAdmin
                    status
                    type
                    createdAt
                    updatedAt
                    updatedBy
                }
            }
        """
        variables = {
            "roleId": "7774efc2-0a6e-11ec-9dc1-0242ac120002",
        }
        payload = {"query": query, "variables": variables}
        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_role_detection(self):
        query = """
            query detection( $name: String){
                detection (name: $name){
                    roles
                }
            }
        """
        # variables = {"name": "GWI Account Manager"}
        variables = {}
        payload = {"query": query, "variables": variables}
        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_get_users_graphql(self):
        query = """
            query users(
                    $pageSize: Int
                    $pageNumber: Int
                    $roleId: [String]
                    $roleName: [String]
                    $roleType: [Int]
                    $roleStatus: Boolean
                    $isAdminRole: Boolean
                    $ownerId: [String]
                    $relationshipType: Int
                    $relationshipStatus: Boolean
                ){
                users(
                    pageSize: $pageSize
                    pageNumber: $pageNumber
                    roleId: $roleId
                    roleName: $roleName
                    roleType: $roleType
                    roleStatus: $roleStatus
                    isAdminRole: $isAdminRole
                    ownerId: $ownerId
                    relationshipType: $relationshipType
                    relationshipStatus: $relationshipStatus
                ){
                    items {
                        name
                        type
                        status
                        users
                    }
                    pageSize
                    pageNumber
                    total
                }
            }
        """
        variables = {
            "pageSize": 10,
            "pageNumber": 1,
            # # "roleId": ["cc1d018b-0af8-11ec-bb01-5d5264ad5593"],
            # # "roleName": ["GWI QC Manager"],
            # "roleType": [1, 2],
            # "roleStatus": True,
            # "isAdminRole": True,
            # "ownerId": ["2018"],
            # "relationshipType": 3,
            # # "relationshipStatus": True,
            "isAdminRole": True,
            "roleType": [1, 2, 3],
            "roleStatus": True,
            "relationshipType": 3,
        }
        payload = {"query": query, "variables": variables}
        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_create_role(self):
        mutation = """
            mutation createRole(
                    $type: Int!
                    $isAdmin: Boolean!
                    $name: String!,
                    $permissions: [PermissionInputType]!
                    $updatedBy: String
                    $dscription: String
                    $status: Boolean
                ) {
                createRole(
                    name: $name,
                    permissions: $permissions
                    updatedBy: $updatedBy
                    roleDescription: $dscription
                    status: $status
                    roleType: $type
                    isAdmin: $isAdmin
                ) {
                    role{
                        roleId
                        name
                        type
                        isAdmin
                        description
                        permissions {
                            resourceId
                            permissions {
                                operation
                                operationName
                                exclude
                            }
                        }
                        status
                        createdAt
                        updatedAt
                        updatedBy
                    }
                }
            }
        """

        variables = {
            "name": "GWI Account Manager",
            "type": 0,
            "isAdmin": True,
            "permissions": [
                {
                    "resourceId": "db1d5fcb2d0b692f2a423e2f2ae23247",
                    "permissions": [
                        {
                            "operationName": "paginateProducts",
                            "operation": "query",
                            "exclude": [],
                        },
                        {
                            "operationName": "showProduct",
                            "exclude": [],
                            "operation": "query",
                        },
                    ],
                },
            ],
            "updatedBy": "setup",
            "description": "Product manager",
        }

        payload = {"mutation": mutation, "variables": variables}
        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_update_role(self):
        mutation = """
            mutation pdateRole(
                $roleId: String!
                $type: Int
                $isAdmin: Boolean
                $name: String
                $permissions: [PermissionInputType]
                $updatedBy: String
                $description: String
                $status: Boolean
            ) {
                updateRole(
                    roleId: $roleId
                    name: $name
                    permissions: $permissions
                    updatedBy: $updatedBy
                    roleDescription: $description
                    status: $status
                    roleType: $type
                    isAdmin: $isAdmin
                ) {
                    role{
                        roleId
                        name
                        type
                        isAdmin
                        description
                        permissions {
                            resourceId
                            permissions {
                                operation
                                operationName
                                exclude
                            }
                        }
                        status
                        createdAt
                        updatedAt
                        updatedBy
                    }
                }
            }
        """
        variables = {
            # "roleId": "7774efc2-0a6e-11ec-9dc1-0242ac120002",
            # "permissions": [
            #     {
            #         "resourceId": "db1d5fcb2d0b692f2a423e2f2ae23247",
            #         "permissions": [
            #             {
            #                 "operation": "query",
            #                 "operationName": "paginateProducts",
            #                 "exclude": [],
            #             },
            #             {
            #                 "operation": "query",
            #                 "operationName": "showProduct",
            #                 "exclude": ["companyCode"],
            #             },
            #         ],
            #     },
            # ],
            "roleId": "cc1d018b-0af8-11ec-bb01-5d5264ad5593",
            "name": "GWI QC Manager",
            "description": "GWI QC Manager 123",
        }
        payload = {"mutation": mutation, "variables": variables}
        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_delete_role(self):
        mutation = """
            mutation deleteRole($roleId: String!) {
                deleteRole (roleId: $roleId) {
                    ok
                }
            }
        """
        variables = {
            "roleId": "bae6a6a2-0a6d-11ec-8d90-0242ac120002",
        }
        payload = {"mutation": mutation, "variables": variables}
        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_create_relationship(self):
        mutation = """
            mutation createRelationship(
                    $roleId: String!,
                    $groupId: String,
                    $userId: String!,
                    $updatedBy: String
                    $status: Boolean
                ) {
                createRelationship(
                    groupId: $groupId,
                    userId: $userId,
                    roleId: $roleId,
                    updatedBy: $updatedBy
                    status: $status
                ) {
                    relationship{
                        relationshipId
                        groupId
                        userId
                        roleId
                        updatedBy
                        status
                    }
                }
            }
        """
        variables = {
            "groupId": None,
            "userId": "076de22a-6eed-4836-b4bb-ec06f1274311",
            "roleId": "7774efc2-0a6e-11ec-9dc1-0242ac120002",
            "updatedBy": "setup",
            "status": True,
        }
        payload = {"mutation": mutation, "variables": variables}
        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_update_relationship(self):
        mutation = """
            mutation updateRelationship(
                    $relationshipId: String!,
                    $groupId: String
                    $userId: String
                    $roleId: String
                    $status: Boolean
                ) {
                updateRelationship(
                    groupId: $groupId,
                    relationshipId: $relationshipId
                    userId: $userId
                    roleId: $roleId
                    status: $status
                ) {
                    relationship{
                        relationshipId
                        groupId
                        userId
                        roleId
                        status
                        updatedBy
                        updatedAt
                    }
                }
            }
        """

        variables = {
            "relationshipId": "a00bb2ac-0a70-11ec-8c56-0242ac120002",
            "groupId": "357",
        }

        payload = {"mutation": mutation, "variables": variables}
        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_delete_relationship(self):
        mutation = """
            mutation deleteRelationship(
                    $relationshipId: String!
                ) {
                deleteRelationship(
                    relationshipId: $relationshipId
                ) {
                    ok
                }
            }
        """

        variables = {
            "relationshipId": "a00bb2ac-0a70-11ec-8c56-0242ac120002",
        }
        payload = {"mutation": mutation, "variables": variables}
        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_save_relationships(self):
        mutation = """
            mutation saveRelationships(
                    $relationships: [RelationshipInputType]!
                ) {
                saveRelationships(
                    relationships: $relationships,
                ) {
                    ok
                }
            }
        """
        variables = {
            "relationships": [
                {
                    "userId": 131,
                    "type": 2,
                    "groupId": "470",
                    "roleId": "c2aeb298-3838-11ec-bbb5-2dc20eac8243",
                },
                {
                    "userId": 131,
                    "type": 2,
                    "groupId": "479",
                    "roleId": "1632a53b-3309-11ec-9501-1b1569b5c836",
                },
            ]
        }
        payload = {"mutation": mutation, "variables": variables}
        response = self.auth.role_graphql(**payload)
        logger.info(response)

    @unittest.skip("demonstrating skipping")
    def test_certificate(self):
        query = """
            query certificate(
                    $username: String!,
                    $password: String!
                ) {
                certificate(
                    username: $username,
                    password: $password
                ) {
                   idToken
                   refreshToken
                   permissions
                   context
                   expiresIn
                }
            }
        """

        variables = {
            "username": os.getenv("test_username"),
            "password": os.getenv("test_user_password"),
        }
        payload = {"query": query, "variables": variables}
        response = self.auth.login_graphql(**payload)
        print(response)
        print("##############")

    @unittest.skip("demonstrating skipping")
    def test_authorize(self):
        request = {
            "type": "REQUEST",
            "methodArn": "arn:aws:execute-api:us-east-1:785238679596:3fizlvttp4/beta/POST/core/api/company_engine_graphql",
            "resource": "/{area}/{endpoint_id}/{proxy+}",
            "path": "/core/api/company_engine_graphql",
            "httpMethod": "ANY",
            "headers": {
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Authorization": "eyJraWQiOiJyUmhLMlhzWm5hNkZjR09za1UxUFNOK3FvUHY5YnRUS2tDRTBxOGJSRDhBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI0OTc4MDU2Ny0yMjA4LTQ5MjItOGMxMi1iMjgzZTY5NTQzYzYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwic192ZW5kb3JfaWQiOiJTMTA3NjMiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9HTXZVaGF4UnMiLCJjb2duaXRvOnVzZXJuYW1lIjoiZWR3YXJkQG1hZ2lueC5jb20iLCJpc19hZG1pbiI6IjAiLCJhdWQiOiJldDNpMXRwYmJtYjQxZW9ncmRscDVxY3NqIiwiZXZlbnRfaWQiOiIwZWE0MTA4MS1hNDNiLTQyNWUtYjkzOC02NDViZTcwYzk4NDAiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTYyODcyOTY5MSwiZXhwIjoxNjI4ODAxNjkxLCJpYXQiOjE2Mjg3Mjk2OTEsInNlbGxlcl9pZCI6IjIwMTgiLCJlbWFpbCI6ImVkd2FyZEBtYWdpbnguY29tIn0.r4eJS_v4cfRijgMlZ72wvjqOFX3iNTYRTxHcqDReEQpY3kQcHybQI1e4k0S2Zk784b1C82D0fnMOr0Tsl_tctdLVZCyt17sjtgiBGZldNkBBBbKrF6ChJQzOFwscfu6BfeyqDLSk_bShDh8_45ili2aKZ0TE95ASGBoc2gPu9XqhqzC2b3ZpoA2m9iHJMdIij0l9VsYoSYKHb59KAA9eonfFhIJHmuVfskD_OGXcsiYMIzMxDeg0vfhO97gBQVSytkne-OhDfu6iREKAeGII2E7hQ4Nc4cq6MkviHBaF_AAtVgHMAb22DHchKnsJf9zE5qsgPuwcgk907FrL7arCcg",
                "CloudFront-Forwarded-Proto": "https",
                "CloudFront-Is-Desktop-Viewer": "true",
                "CloudFront-Is-Mobile-Viewer": "false",
                "CloudFront-Is-SmartTV-Viewer": "false",
                "CloudFront-Is-Tablet-Viewer": "false",
                "CloudFront-Viewer-Country": "CN",
                "Content-Length": "2944",
                "content-type": "application/json",
                "Host": "3fizlvttp4.execute-api.us-east-1.amazonaws.com",
                "origin": "http://localhost:3000",
                "Referer": "http://localhost:3000/",
                "sec-ch-ua": '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
                "sec-ch-ua-mobile": "?0",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "cross-site",
                "seller_id": "2018",
                "team_id": "357",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
                "Via": "2.0 feda34dcbf6a00e232656b7983c2c7f0.cloudfront.net (CloudFront)",
                "X-Amz-Cf-Id": "s9x8PP20Kle9SssxG70yk9hag6GZjNkycKyNL6jSN3UVJyAoJT9dUA==",
                "X-Amzn-Trace-Id": "Root=1-6114dc3f-19c01adf1f4423e86881251a",
                "x-api-key": "dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4",
                "X-Forwarded-For": "220.191.46.189, 130.176.132.189",
                "X-Forwarded-Port": "443",
                "X-Forwarded-Proto": "https",
            },
            "multiValueHeaders": {
                "Accept": ["application/json, text/plain, */*"],
                "Accept-Encoding": ["gzip, deflate, br"],
                "Accept-Language": ["zh-CN,zh;q=0.9"],
                "Authorization": [
                    "eyJraWQiOiJyUmhLMlhzWm5hNkZjR09za1UxUFNOK3FvUHY5YnRUS2tDRTBxOGJSRDhBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI0OTc4MDU2Ny0yMjA4LTQ5MjItOGMxMi1iMjgzZTY5NTQzYzYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwic192ZW5kb3JfaWQiOiJTMTA3NjMiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9HTXZVaGF4UnMiLCJjb2duaXRvOnVzZXJuYW1lIjoiZWR3YXJkQG1hZ2lueC5jb20iLCJpc19hZG1pbiI6IjAiLCJhdWQiOiJldDNpMXRwYmJtYjQxZW9ncmRscDVxY3NqIiwiZXZlbnRfaWQiOiIwZWE0MTA4MS1hNDNiLTQyNWUtYjkzOC02NDViZTcwYzk4NDAiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTYyODcyOTY5MSwiZXhwIjoxNjI4ODAxNjkxLCJpYXQiOjE2Mjg3Mjk2OTEsInNlbGxlcl9pZCI6IjIwMTgiLCJlbWFpbCI6ImVkd2FyZEBtYWdpbnguY29tIn0.r4eJS_v4cfRijgMlZ72wvjqOFX3iNTYRTxHcqDReEQpY3kQcHybQI1e4k0S2Zk784b1C82D0fnMOr0Tsl_tctdLVZCyt17sjtgiBGZldNkBBBbKrF6ChJQzOFwscfu6BfeyqDLSk_bShDh8_45ili2aKZ0TE95ASGBoc2gPu9XqhqzC2b3ZpoA2m9iHJMdIij0l9VsYoSYKHb59KAA9eonfFhIJHmuVfskD_OGXcsiYMIzMxDeg0vfhO97gBQVSytkne-OhDfu6iREKAeGII2E7hQ4Nc4cq6MkviHBaF_AAtVgHMAb22DHchKnsJf9zE5qsgPuwcgk907FrL7arCcg"
                ],
                "CloudFront-Forwarded-Proto": ["https"],
                "CloudFront-Is-Desktop-Viewer": ["true"],
                "CloudFront-Is-Mobile-Viewer": ["false"],
                "CloudFront-Is-SmartTV-Viewer": ["false"],
                "CloudFront-Is-Tablet-Viewer": ["false"],
                "CloudFront-Viewer-Country": ["CN"],
                "Content-Length": ["2944"],
                "content-type": ["application/json"],
                "Host": ["3fizlvttp4.execute-api.us-east-1.amazonaws.com"],
                "origin": ["http://localhost:3000"],
                "Referer": ["http://localhost:3000/"],
                "sec-ch-ua": [
                    '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"'
                ],
                "sec-ch-ua-mobile": ["?0"],
                "sec-fetch-dest": ["empty"],
                "sec-fetch-mode": ["cors"],
                "sec-fetch-site": ["cross-site"],
                "seller_id": ["2018"],
                "team_id": ["357"],
                "User-Agent": [
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"
                ],
                "Via": [
                    "2.0 feda34dcbf6a00e232656b7983c2c7f0.cloudfront.net (CloudFront)"
                ],
                "X-Amz-Cf-Id": [
                    "s9x8PP20Kle9SssxG70yk9hag6GZjNkycKyNL6jSN3UVJyAoJT9dUA=="
                ],
                "X-Amzn-Trace-Id": ["Root=1-6114dc3f-19c01adf1f4423e86881251a"],
                "x-api-key": ["dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4"],
                "X-Forwarded-For": ["220.191.46.189, 130.176.132.189"],
                "X-Forwarded-Port": ["443"],
                "X-Forwarded-Proto": ["https"],
            },
            "queryStringParameters": {},
            "multiValueQueryStringParameters": {},
            "pathParameters": {
                "area": "core",
                "proxy": "company_engine_graphql",
                "endpoint_id": "api",
            },
            "stageVariables": {},
            "requestContext": {
                "resourceId": "d5y1px",
                "resourcePath": "/{area}/{endpoint_id}/{proxy+}",
                "httpMethod": "POST",
                "extendedRequestId": "D8daBGpQoAMFwXg=",
                "requestTime": "12/Aug/2021:08:30:55 +0000",
                "path": "/beta/core/api/company_engine_graphql",
                "accountId": "785238679596",
                "protocol": "HTTP/1.1",
                "stage": "beta",
                "domainPrefix": "3fizlvttp4",
                "requestTimeEpoch": 1628757055955,
                "requestId": "d925a6f0-e7d9-414f-acbe-31f4c379bd07",
                "identity": {
                    "cognitoIdentityPoolId": None,
                    "cognitoIdentityId": None,
                    "apiKey": "dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4",
                    "principalOrgId": None,
                    "cognitoAuthenticationType": None,
                    "userArn": None,
                    "apiKeyId": "faqkldfbx7",
                    "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
                    "accountId": None,
                    "caller": None,
                    "sourceIp": "220.191.46.189",
                    "accessKey": None,
                    "cognitoAuthenticationProvider": None,
                    "user": None,
                },
                "domainName": "3fizlvttp4.execute-api.us-east-1.amazonaws.com",
                "apiId": "3fizlvttp4",
            },
            "fnConfigurations": {
                "area": "core",
                "aws_lambda_arn": "arn:aws:lambda:us-east-1:785238679596:function:silvaengine_microcore",
                "config": {
                    "auth_required": False,
                    "class_name": "CompanyEngine",
                    "funct_type": "RequestResponse",
                    "graphql": False,
                    "methods": ["GET", "POST"],
                    "module_name": "company_engine",
                    "setting": "seller_engine_graphql",
                },
                "function": "company_engine_graphql",
            },
        }

        response = self.auth.authorize(request, None)
        print("Response:", response)

    @unittest.skip("demonstrating skipping")
    def test_verify_permissions(self):
        request = {
            "resource": "/{area}/{endpoint_id}/{proxy+}",
            "path": "/core/api/data_engine_graphql",
            "httpMethod": "POST",
            "headers": {
                "Accept": "application/json",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "zh-CN",
                "Authorization": "eyJraWQiOiJyUmhLMlhzWm5hNkZjR09za1UxUFNOK3FvUHY5YnRUS2tDRTBxOGJSRDhBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI3MWMzNTU5Yi01ZWYxLTRiMGEtOGI1MS05YjQzOWE1N2ZmYmYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfR012VWhheFJzIiwiY29nbml0bzp1c2VybmFtZSI6ImpuZ0BpbmdyZWRpZW50c29ubGluZS5jb20iLCJpc19hZG1pbiI6IjEiLCJhdWQiOiJldDNpMXRwYmJtYjQxZW9ncmRscDVxY3NqIiwiZXZlbnRfaWQiOiJlYTVkODEzMy01NTQyLTQ4NGYtOTBiMy1iZTg5NTZlZjUyODQiLCJ1c2VyX2lkIjoiMTE4IiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE2Mjk4MjA2MDcsImV4cCI6MTYyOTg5MjYwNywiaWF0IjoxNjI5ODIwNjA3LCJlbWFpbCI6ImpuZ0BpbmdyZWRpZW50c29ubGluZS5jb20ifQ.RLQaFgLc3KbEXHMocNj5TGKpPVihJH8ZYRlDgnqi_6IY-eNTqjDAV5YXW-4LRVSP4zDrkUxENNcfcda-iguPRPcHOcIlyQKzcI0n8Cxu2aUfIwOSbiG0UjGgaa73SJpUqmwUsEq_BENG1oyuKiYr0fQc58Z5Wb9sFZNCA1HlE6uqohGb6LOfgrOKXytpuxAgWg2321gMPB1aTrTsFeYpOPce4lv7reBu_PPUr7OBS3DH63RL-S393E9Y2O4anCaAdrn10Tq_j7uLfpLtgTX7JyQO4FRugvxK7bPlkEbNeeS0sauerGHlJ5EXY8XLsx4duIKFD4fLArm8-6vrUW_Q_w",
                "CloudFront-Forwarded-Proto": "https",
                "CloudFront-Is-Desktop-Viewer": "true",
                "CloudFront-Is-Mobile-Viewer": "false",
                "CloudFront-Is-SmartTV-Viewer": "false",
                "CloudFront-Is-Tablet-Viewer": "false",
                "CloudFront-Viewer-Country": "HK",
                "content-type": "application/json",
                "Host": "3fizlvttp4.execute-api.us-east-1.amazonaws.com",
                "origin": "electron://altair",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "cross-site",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AltairGraphQLClient/4.0.9 Chrome/89.0.4389.82 Electron/12.0.1 Safari/537.36",
                "Via": "2.0 da2930182b81a0969bededaf2726cadc.cloudfront.net (CloudFront)",
                "X-Amz-Cf-Id": "A3z-Ef_o89je2FfMudkio2PP2X2NheRSFVwU0kMoQ8hDluzpg3NocQ==",
                "X-Amzn-Trace-Id": "Root=1-61258e7f-600f8e344c290daa06acb931",
                "x-api-key": "dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4",
                "X-Forwarded-For": "103.97.201.121, 130.176.93.156",
                "X-Forwarded-Port": "443",
                "X-Forwarded-Proto": "https",
            },
            "multiValueHeaders": {
                "Accept": ["application/json"],
                "Accept-Encoding": ["gzip, deflate, br"],
                "Accept-Language": ["zh-CN"],
                "Authorization": [
                    "eyJraWQiOiJyUmhLMlhzWm5hNkZjR09za1UxUFNOK3FvUHY5YnRUS2tDRTBxOGJSRDhBPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI3MWMzNTU5Yi01ZWYxLTRiMGEtOGI1MS05YjQzOWE1N2ZmYmYiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfR012VWhheFJzIiwiY29nbml0bzp1c2VybmFtZSI6ImpuZ0BpbmdyZWRpZW50c29ubGluZS5jb20iLCJpc19hZG1pbiI6IjEiLCJhdWQiOiJldDNpMXRwYmJtYjQxZW9ncmRscDVxY3NqIiwiZXZlbnRfaWQiOiJlYTVkODEzMy01NTQyLTQ4NGYtOTBiMy1iZTg5NTZlZjUyODQiLCJ1c2VyX2lkIjoiMTE4IiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE2Mjk4MjA2MDcsImV4cCI6MTYyOTg5MjYwNywiaWF0IjoxNjI5ODIwNjA3LCJlbWFpbCI6ImpuZ0BpbmdyZWRpZW50c29ubGluZS5jb20ifQ.RLQaFgLc3KbEXHMocNj5TGKpPVihJH8ZYRlDgnqi_6IY-eNTqjDAV5YXW-4LRVSP4zDrkUxENNcfcda-iguPRPcHOcIlyQKzcI0n8Cxu2aUfIwOSbiG0UjGgaa73SJpUqmwUsEq_BENG1oyuKiYr0fQc58Z5Wb9sFZNCA1HlE6uqohGb6LOfgrOKXytpuxAgWg2321gMPB1aTrTsFeYpOPce4lv7reBu_PPUr7OBS3DH63RL-S393E9Y2O4anCaAdrn10Tq_j7uLfpLtgTX7JyQO4FRugvxK7bPlkEbNeeS0sauerGHlJ5EXY8XLsx4duIKFD4fLArm8-6vrUW_Q_w"
                ],
                "CloudFront-Forwarded-Proto": ["https"],
                "CloudFront-Is-Desktop-Viewer": ["true"],
                "CloudFront-Is-Mobile-Viewer": ["false"],
                "CloudFront-Is-SmartTV-Viewer": ["false"],
                "CloudFront-Is-Tablet-Viewer": ["false"],
                "CloudFront-Viewer-Country": ["HK"],
                "content-type": ["application/json"],
                "Host": ["3fizlvttp4.execute-api.us-east-1.amazonaws.com"],
                "origin": ["electron://altair"],
                "sec-fetch-dest": ["empty"],
                "sec-fetch-mode": ["cors"],
                "sec-fetch-site": ["cross-site"],
                "User-Agent": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AltairGraphQLClient/4.0.9 Chrome/89.0.4389.82 Electron/12.0.1 Safari/537.36"
                ],
                "Via": [
                    "2.0 da2930182b81a0969bededaf2726cadc.cloudfront.net (CloudFront)"
                ],
                "X-Amz-Cf-Id": [
                    "A3z-Ef_o89je2FfMudkio2PP2X2NheRSFVwU0kMoQ8hDluzpg3NocQ=="
                ],
                "X-Amzn-Trace-Id": ["Root=1-61258e7f-600f8e344c290daa06acb931"],
                "x-api-key": ["dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4"],
                "X-Forwarded-For": ["103.97.201.121, 130.176.93.156"],
                "X-Forwarded-Port": ["443"],
                "X-Forwarded-Proto": ["https"],
            },
            "queryStringParameters": None,
            "multiValueQueryStringParameters": None,
            "pathParameters": {
                "area": "core",
                "proxy": "data_engine_graphql",
                "endpoint_id": "api",
            },
            "stageVariables": None,
            "requestContext": {
                "resourceId": "d5y1px",
                "authorizer": {
                    "sub": "71c3559b-5ef1-4b0a-8b51-9b439a57ffbf",
                    "email_verified": "true",
                    "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_GMvUhaxRs",
                    "principalId": "/core/api/data_engine_graphql",
                    "cognito:username": "jng@ingredientsonline.com",
                    "integrationLatency": 5037,
                    "is_admin": "1",
                    "aud": "et3i1tpbbmb41eogrdlp5qcsj",
                    "event_id": "ea5d8133-5542-484f-90b3-be8956ef5284",
                    "user_id": "118",
                    "token_use": "id",
                    "auth_time": "1629820607",
                    "exp": "1629892607",
                    "iat": "1629820607",
                    "email": "jng@ingredientsonline.com",
                },
                "resourcePath": "/{area}/{endpoint_id}/{proxy+}",
                "httpMethod": "POST",
                "extendedRequestId": "EmMz8FiOIAMFmhA=",
                "requestTime": "25/Aug/2021:00:27:43 +0000",
                "path": "/beta/core/api/data_engine_graphql",
                "accountId": "785238679596",
                "protocol": "HTTP/1.1",
                "stage": "beta",
                "domainPrefix": "3fizlvttp4",
                "requestTimeEpoch": 1629851263492,
                "requestId": "5e6a27e8-83a1-4a00-96aa-5cf23794b267",
                "identity": {
                    "cognitoIdentityPoolId": None,
                    "cognitoIdentityId": None,
                    "apiKey": "dxt9direVp4QEfg3ZpzI7SetPXYHNGGadgJ5dGu4",
                    "principalOrgId": None,
                    "cognitoAuthenticationType": None,
                    "userArn": None,
                    "apiKeyId": "faqkldfbx7",
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AltairGraphQLClient/4.0.9 Chrome/89.0.4389.82 Electron/12.0.1 Safari/537.36",
                    "accountId": None,
                    "caller": None,
                    "sourceIp": "103.97.201.121",
                    "accessKey": None,
                    "cognitoAuthenticationProvider": None,
                    "user": None,
                },
                "domainName": "3fizlvttp4.execute-api.us-east-1.amazonaws.com",
                "apiId": "3fizlvttp4",
            },
            "body": '{"query":"query {\\n  dataCenter {\\n    countries {\\n      lookupId\\n      lookupName\\n      lookupCode\\n      sortOrder\\n      custom1\\n      custom2\\n      custom3\\n    }\\n    freightTerms {\\n      lookupId\\n      lookupName\\n    }\\n    declineReasons {\\n      lookupId\\n      lookupName\\n    }\\n    paymentTypes {\\n      lookupId\\n      lookupName\\n    }\\n    paymentCycles {\\n      key\\n      value\\n    }\\n    documents {\\n      edges {\\n        node {\\n          docTypeGroupId\\n          docTypeGroup\\n          documentTypes {\\n            edges {\\n              node {\\n                docTypeId\\n                typeName\\n                requiredFlag\\n                sortOrder\\n                forQc\\n                forProduct\\n                forFactory\\n                forShipment\\n                uploadOnlyFlag\\n                docPrefix\\n                expireFlag\\n                docTypeGroupId\\n              }\\n            }\\n          }\\n        }\\n      }\\n    }\\n  }\\n}","variables":{},"operationName":null}',
            "isBase64Encoded": False,
            "fnConfigurations": {
                "area": "core",
                "aws_lambda_arn": "arn:aws:lambda:us-east-1:785238679596:function:silvaengine_microcore",
                "config": {
                    "auth_required": True,
                    "class_name": "DataEngine",
                    "funct_type": "RequestResponse",
                    "graphql": True,
                    "methods": ["POST"],
                    "module_name": "data_engine",
                    "operations": {"mutation": [], "query": ["dataCenter"]},
                    "setting": "product_engine_graphql",
                },
                "function": "data_engine_graphql",
            },
        }
        response = self.auth.verify_permission(request, None)
        print("Response:", response)

    @unittest.skip("demonstrating skipping")
    def test_get_roles(self):
        response = self.auth.get_roles_by_cognito_user_sub(
            "f2b3a074-eb9e-4210-81b2-cbe617ecc50b"
        )
        print("Response:", response)

    @unittest.skip("demonstrating skipping")
    def test_get_users(self):
        response = self.auth.get_users_by_role_type(
            role_types=[2], relationship_type=1, ids=[2018]
        )
        print("Response:", response)

    @unittest.skip("demonstrating skipping")
    def test_get_roles_by_specific_user(self):
        response = self.auth.get_roles_by_specific_user(
            1906, RoleRelationshipType.SELLER.value
        )
        print("test_get_roles_by_specific_user:::::", response)

    @unittest.skip("demonstrating skipping")
    def test_check_user_permissions(self):
        response = self.auth.check_user_permissions(
            "crm_engine",
            "CRMEngine",
            "crm_graphql",
            "mutation",
            "insertCustomer",
            2,
            2086,
            204,
        )
        print("test_check_user_permissions:::::", response)


if __name__ == "__main__":
    unittest.main()
