import pathlib
import sys

sys.path.append(
    pathlib.Path(__file__).parent.parent.__str__()
)
from datetime import time

import fastapi

import cy_web
cy_web.create_web_app(
    working_dir= pathlib.Path(__file__).parent.__str__(),
    host_url="http://localhost:5011",
    static_dir="./static",
    template_dir="./templates",
    logs_dir="./logs",
    dev_mode=True,
    bind="0.0.0.0:5011"


)
# @cy_web.middleware()
# async def test(request: fastapi.Request, call_next):
#     start_time = time.time()
#     response = await call_next(request)
#     process_time = time.time() - start_time
#     response.headers["X-Process-Time"] = str(process_time)
#     return response
cy_web.load_controller_from_dir("api","./controllers")
@cy_web.auth_account()
def verify_account(username:str,password:str):
    return dict(
        application='a',
        is_ok=True,
        username =username

    )
if __name__ =="__main__":
    cy_web.start_with_uvicorn()