# import fastapi
# from typing import Optional,List
# import cy_web
# from example.controllers.models.users import Users
# @cy_web.hanlder("post","{tanent_name}/file/create")
# def create_user(tanent_name:str,file:fastapi.UploadFile=fastapi.File())->Users:
#     return Users(
#
#     )
# @cy_web.hanlder("post","{tanent_name}/files/create")
# def create_user(tanent_name,file: List[fastapi.UploadFile]=fastapi.File(...))->Users:
#     return Users(
#
#     )