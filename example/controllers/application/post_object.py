import uuid

import cy_web
from typing import List
import pydantic
from example.controllers.models.users import Users
from typing import Optional
import typing
@cy_web.hanlder("post","{tanent_name}/user/create")
def create_user(tanent_name:str,user:Users,token = cy_web.auth())->Users:
    return Users(

    )