import pathlib
from typing import List
import sys
sys.path.append(pathlib.Path(__file__).parent.__str__())
import cy_web_x
def create_web_app(
        working_dir:str,
        host_url:str,
        static_dir:str,
        template_dir:str,
        logs_dir:str,
        bind:str,
        url_get_token: str = "api/accounts/token",
        jwt_algorithm: str = "HS256",
        jwt_secret_key: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7",
        dev_mode:bool =False
):
    ret = cy_web_x.WebApp(

        working_dir=working_dir,
        host_url=host_url,
        static_dir=static_dir,
        template_dir=template_dir,
        logs_dir="./logs",
        dev_mode=dev_mode,
        url_get_token=url_get_token,
        jwt_algorithm =jwt_algorithm,
        jwt_secret_key =jwt_secret_key,
        bind=bind

    )
    return ret
def hanlder(method:str,path:str):
    return cy_web_x.web_handler(
        method=method,
        path=path
    )


def load_controller_from_dir(prefix, path):
    return cy_web_x.load_controller_from_dir(
        prefix,
        path
    )


def start_with_uvicorn():
    cy_web_x.start_with_uvicorn()


def middleware():
    return cy_web_x.middleware()
def auth():
    """
    Set require auth on api handler
    :return:
    """
    return cy_web_x.auth()
def auth_account():
    """
    Code decorate for on aoyhthenti cate token
    :return:
    """
    return cy_web_x.auth_account()
def add_cors(origins:List[str]):
    return cy_web_x.add_cors(origins)