import cy_web
from typing import List
import pydantic
class ApplicationInfo(pydantic.BaseModel):
    Name:str
@cy_web.hanlder("post","apps")
def list_of_apps(apps:List[ApplicationInfo],token=cy_web.auth())->List[int]:
    return token