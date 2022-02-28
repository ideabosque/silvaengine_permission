#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from enum import Enum

__author__ = "bl"


class RoleType(Enum):
    NORMAL = 0
    ACCOUNT_MANAGER = 1
    QC_MANAGER = 2
    DEPT_MANAGER = 3


class RoleRelationshipType(Enum):
    ADMINISTRATOR = 0
    SELLER = 1
    COMPANY = 2
    FACTORY = 3
    PRE_ASSIGN_SELLER = 4


class SwitchStatus(Enum):
    YES = 1
    NO = 0
