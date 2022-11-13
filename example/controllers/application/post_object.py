
import cy_web
from example.controllers.models.users import Users
@cy_web.hanlder("post","{tanent_name}/user/create")
def create_user(tanent_name:str,user:Users,token = cy_web.auth())->Users:
    return Users(

    )