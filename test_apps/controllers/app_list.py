import cy_web
from typing import List
class ApplicationInfo:
    Name:str
@cy_web.hanlder("post","apps")
def list_of_apps(token=cy_web.auth())->ApplicationInfo:
    return token