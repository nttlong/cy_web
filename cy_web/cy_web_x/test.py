import fastapi
import pydantic

import cy_web_x
fx=cy_web_x.WebApp(


    working_dir= r"C:\code\python\cy_web\test_apps",
    host_url="http://localhost:5011",
    static_dir="./static",
    template_dir="./templates",
    logs_dir="./logs",
    dev_mode=True,
    bind="0.0.0.0:5011"


)
# @fx.auth()
# def test(cls, request:fastapi.Request):
#     print("OK")
def test(a:str,b=1):
    print(a)
def fx1(x=fastapi.Depends(fx.oauth2_type)):
    return
cy_web_x.load_controller_from_dir("api","./controllers")
@cy_web_x.auth_account()
def ok(username:str,password:str):
    return dict(
        username=username,
        application='admin',
        is_ok = True

    )


class MyClass(pydantic.BaseModel):
    pass

my_app =cy_web_x.fast_api()
def test():
    return 1
fx=my_app.post(path="test",response_model=MyClass)(test)

fy = fx
if __name__ =="__main__":
    cy_web_x.start_with_uvicorn()
    cy_web_x.web_handler(
        method="post",
        path="aa"

    )
