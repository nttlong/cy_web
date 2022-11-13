import cy_web
from typing import List
import pydantic
from test_apps.web_models.apps import AppInfo
class ApplicationInfo(pydantic.BaseModel):
    Name:str
@cy_web.hanlder("post","apps")
def list_of_apps(code:str,token=cy_web.auth())->List[int]:
    return [1,2,3]