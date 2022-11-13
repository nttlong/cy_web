import logging
from fastapi.exceptions import HTTPException
from typing import List
import typing
import uvicorn
import jose
from jose import JWTError, jwt
import threading
from datetime import datetime
import inspect
import fastapi
import pydantic
import sys

__wrap_pydantic_cache__ = {}
__wrap_pydantic_lock__ = threading.Lock()


def __wrap_pydantic__(pre, cls, is_lock=True):
    global __wrap_pydantic_cache__
    global __wrap_pydantic_lock__
    if cls.__module__ ==typing.__name__  and cls.__origin__==list:
        for x in cls.__args__:
            __wrap_pydantic__("",x)
        return
    if __wrap_pydantic_cache__.get(f"{cls.__module__}/{cls.__name__}") and is_lock:
        return __wrap_pydantic_cache__.get(f"{cls.__module__}/{cls.__name__}")
    with __wrap_pydantic_lock__:
        if hasattr(cls, "__origin__"):
            print(cls)
        if hasattr(cls, "__annotations__"):
            ls = list(cls.__dict__.items())
            for k, v in ls:
                if not (k[0:2] == "__" and k[:-2] != "__") and v not in [str, int, datetime, bool,
                                                                         float] and inspect.isclass(v):
                    re_modify = __wrap_pydantic__(cls.__name__, v, False)
                    cls.__annotations__[k] = re_modify
                    setattr(sys.modules[cls.__module__], k, re_modify)

            for k, v in cls.__annotations__.items():
                if v not in [str, int, datetime, bool, float] and inspect.isclass(v):
                    if cls.__annotations__.get(k) is None:
                        re_modify = __wrap_pydantic__(cls.__name__, v, False)
                        cls.__annotations__[k] = re_modify
                        setattr(sys.modules[cls.__module__], k, re_modify)

        ret_cls = type(f"{cls.__name__}", (cls, pydantic.BaseModel,), dict(cls.__dict__))
        def get_mdl(cls):
            if sys.modules.get(cls.__module__):
                return sys.modules[cls.__module__]
            else:
                for k,v in sys.modules.items():
                    if hasattr(v,"__file__"):
                        if v.__file__==cls.__module__:
                            return v

        cls_module= get_mdl(cls)
        setattr(cls_module, cls.__name__, ret_cls)
        ret_cls.__name__ = cls.__name__
        __wrap_pydantic_cache__[f"{cls.__module__}/{cls.__name__}"] = ret_cls
    return __wrap_pydantic_cache__.get(f"{cls.__module__}/{cls.__name__}")


def check_is_need_pydantic(cls):
    import typing
    if isinstance(cls,tuple):
        ret=False
        for x in cls:
            ret= ret or check_is_need_pydantic(x)
        return ret
    if cls.__module__ == typing.__name__ and cls.__origin__==list and hasattr(cls,"__args__"):
        return check_is_need_pydantic(cls.__args__)
    if cls == fastapi.Request or issubclass(cls, fastapi.Request):
        return False
    if not inspect.isclass(cls) and callable(cls):
        return False
    if hasattr(cls, "__origin__") and cls.__origin__ == typing.List.__origin__ and hasattr(cls,
                                                                                           "__args__") and isinstance(
        cls.__args__, tuple):
        ret = []
        for x in cls.__args__:
            if check_is_need_pydantic(x):
                ret += [__wrap_pydantic__("", x, is_lock=False)]
            else:
                ret += [x]
        cls.__args__ = tuple(ret)

        return False

    ret = (cls not in [str, int, float, datetime, bool, dict]) and (
            inspect.isclass(cls) and (not issubclass(cls, pydantic.BaseModel)))
    return ret


class RequestHandler:

    def __init__(self, method, path, handler):
        self.path = path
        __old_dfs__ = []
        self.return_type = None
        if handler.__defaults__ is not None:
            __old_dfs__ = list(handler.__defaults__)
        __annotations__: dict = handler.__annotations__
        __defaults__ = []

        for k, v in __annotations__.items():

            if method != "form":
                if v == fastapi.Request:
                    continue
                if check_is_need_pydantic(v):
                    handler.__annotations__[k] = __wrap_pydantic__("", v)
                    if k != "return":
                        __defaults__ += [fastapi.Body(title=k)]

                    else:
                        self.return_type = handler.__annotations__[k]

            else:
                if k == "return":
                    if check_is_need_pydantic(v):
                        handler.__annotations__[k] = __wrap_pydantic__("", v)

                if not "{" + k + "}" in self.path:
                    import typing
                    if v == fastapi.UploadFile or v == fastapi.Request or \
                                (hasattr(v, "__origin__") and v.__origin__ == typing.List[fastapi.UploadFile].__origin__
                                 and hasattr(v, "__args__") and v.__args__[0] == fastapi.UploadFile):
                        continue
                    elif k != "return" and not v in [str, datetime, bool, float, int]:
                        continue
                    elif k != "return":
                        __defaults__ += [fastapi.Form()]
                        # __wrap_pydantic__(handler.__name__, v)

        __defaults__ += __old_dfs__
        # def new_handler(*args,**kwargs):
        #     handler(*args,**kwargs)
        handler.__defaults__ = tuple(__defaults__)
        self.handler = handler
        if method == "form": method = "post"
        self.method = method


def __wrapper_class__(method: str, obj, path: str):
    pass


def __wrapper_func__(method: str, obj, path) -> RequestHandler:
    fx = RequestHandler(method, path, obj)
    return fx

from fastapi import FastAPI, Request

from typing import Optional, Dict
from fastapi.security.oauth2 import OAuth2PasswordBearer

import os
from fastapi.templating import Jinja2Templates


# wellknown_app: FastAPI = None
# __instance__ = None


def load_controller_from_file(file):
    if not os.path.isfile(file):
        print(f"{file} was not found")
        logging.Logger.error(f"{file} was not found")
    pass


class BaseWebApp:
    def __init__(self):
        self.application_name = None
        self.main_module = None
        self.bind_ip = None
        self.bind_port = None
        self.host_url = None
        self.host_api_url = None
        self.host_schema = None
        self.__routers__ = None
        self.app: FastAPI = None
        self.controller_dirs: List[str] = []
        self.logs_dir: str = None
        self.logs: logging.Logger = None
        self.working_dir: str = None
        self.host_dir: str = None
        self.dev_mode: bool = False
        self.api_host_dir = "api"
        self.static_dir: str = None
        self.template_dir: str = None
        self.templates: Jinja2Templates = None
        self.url_get_token: str = None
        self.oauth2: OAuth2PasswordBearerAndCookie = None
        self.jwt_algorithm = "HS256"
        self.jwt_secret_key = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
        self.oauth2_type = None
        self.__on_auth__ = None
        self.request_handlers =dict()
        self.on_auth_user=None




    def load_controller_from_dir(self, route_prefix: str = None, controller_dir: str = None):
        if controller_dir == None:
            return
        if controller_dir[0:2] == "./":
            controller_dir = os.path.join(self.working_dir, controller_dir[2:])
        controller_dir = controller_dir.replace('/',os.sep)
        if not os.path.isdir(controller_dir):
            print(f"{controller_dir} was not found")
            self.logs.error(msg=f"{controller_dir} was not found")
            return
        root_dir, dirs, files = list(os.walk(controller_dir))[0]
        import sys
        sys.path.append(self.working_dir)
        sys.path.append(root_dir)
        for x in dirs:
            sys.path.append(x)
        for _file_ in files:
            self.load_controller_from_file(os.path.join(root_dir, _file_), route_prefix)
        for dir in dirs:
            self.load_controller_module_dir(os.path.join(root_dir, dir), route_prefix)

    def create_logs(self, logs_dir) -> logging.Logger:
        if not os.path.isdir(logs_dir):
            os.makedirs(logs_dir, exist_ok=True)

        _logs = logging.Logger("web")
        hdlr = logging.FileHandler(logs_dir + '/log{}.txt'.format(datetime.strftime(datetime.now(), '%Y%m%d%H%M%S_%f')))
        _logs.addHandler(hdlr)
        return _logs

    def load_controller_module_dir(self, module_dir, prefix: str = None) -> List[object]:

        # import pyx_re_quicky_routers
        module_path = os.path.join(module_dir, "__init__.py")
        _, _, files = list(os.walk(module_dir))[0]
        for _file_ in files:
            if os.path.splitext(_file_)[1] == ".py":
                full_file_path = os.path.join(module_dir, _file_)
                if os.path.isfile(full_file_path):
                    self.load_controller_from_file(full_file_path, prefix)
    def auth(self):
        def wrapper(fn):
            setattr(self.oauth2_type, "__call__", fn)
        return wrapper
    def get_auth(self):
        return self.oauth2_type(
            token_url=self.url_get_token,
            jwt_algorithm=self.jwt_algorithm,
            jwt_secret_key=self.jwt_secret_key
        )

    def load_controller_from_file(self, full_file_path, prefix):
        if not os.path.isfile(full_file_path):
            return
        if os.path.splitext(full_file_path).__len__()!=2 and os.path.splitext(full_file_path)[1]!=".py":
            return

        import importlib.util
        import sys
        spec = importlib.util.spec_from_file_location(full_file_path, full_file_path)
        _mdl_ = importlib.util.module_from_spec(spec)
        sys.modules[_mdl_.__name__]=_mdl_
        spec.loader.exec_module(_mdl_)
        for k, v in _mdl_.__dict__.items():
            if isinstance(v, RequestHandler):

                _path = "/" + v.path
                if prefix is not None and prefix != "":
                    _path = "/" + prefix + _path
                if self.host_dir is not None:
                    _path = self.host_dir + _path
                if v.return_type is None:
                    if hasattr(v.handler, "__annotations__"):
                        if v.handler.__annotations__.get("return") is not None:
                            v.return_type =v.handler.__annotations__.get("return")

                if v.return_type is not None:
                    getattr(self.app, v.method)(_path, response_model=v.return_type)(v.handler)
                else:
                    getattr(self.app, v.method)(_path)(v.handler)
                self.request_handlers[v.path]=v

__cache_apps__ = {}
__cache_apps_lock__ = threading.Lock()
__instance__ = None
web_application = None
from fastapi import Depends, FastAPI, HTTPException, status
from datetime import datetime, timedelta
from typing import Union
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
def create_access_token(data: dict, expires_delta = None,SECRET_KEY=None,ALGORITHM=None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": None})
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    global web_application
    if not isinstance(web_application,WebApp):
        raise Exception("WebApp was not found")
    if web_application.on_auth_user is None:
        raise Exception("Please create on auth user with  cy_web_x.auth_user")
    user = web_application.on_auth_user(form_data.username, form_data.password)
    if not isinstance(user,dict):
        raise Exception(f"{web_application.on_auth_user.__name__} in {web_application.on_auth_user.__code__.co_filename} must return dictionary with username:str and application:str,is_ok:bool")
    if set(["username","application","is_ok"]).intersection(list(user.keys())) != set(["username","application","is_ok"]):
        raise Exception(
            f"{web_application.on_auth_user.__name__} in {web_application.on_auth_user.__code__.co_filename} must return dictionary with username:str and application:str,is_ok:bool")
    if user.get("is_ok") == False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        {
            "username": user.get("username"),
            "application":user.get("application")
        },expires_delta=None,
        SECRET_KEY= web_application.jwt_secret_key,
        ALGORITHM= web_application.jwt_algorithm
    )
    return {"access_token": access_token, "token_type": "bearer"}

class WebApp(BaseWebApp):


    def __init__(self,


                 working_dir: str,
                 bind: str = "0.0.0.0:8011",
                 host_url: str = "http://localhost:8011",
                 logs_dir: str = "./logs",
                 controller_dirs: List[str] = [],
                 api_host_dir: str = "api",
                 static_dir: str = None,
                 dev_mode: bool = False,
                 template_dir: str = None,
                 url_get_token: str = "api/accounts/token",
                 jwt_algorithm: str ="HS256",
                 jwt_secret_key: str =  "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
                 ):
        global __cache_apps__
        global __cache_apps_lock__
        global web_application
        web_application=self
        self.request_handlers = dict()
        self.app =fastapi.FastAPI()
        self.url_get_token = url_get_token
        self.jwt_algorithm = jwt_algorithm
        self.jwt_secret_key = jwt_secret_key
        self.template_dir = template_dir
        self.dev_mode = dev_mode
        self.api_host_dir = api_host_dir


        self.working_dir = working_dir
        self.static_dir = static_dir
        if self.static_dir is not None and self.static_dir[0:2] == "./":
            self.static_dir = os.path.join(self.working_dir, self.static_dir[2:])
        self.logs_dir = logs_dir
        if self.logs_dir[0:2] == "./":
            self.logs_dir = os.path.join(self.working_dir, self.logs_dir[2:])
        self.logs: logging.Logger = self.create_logs(self.logs_dir)
        if bind.split(":").__len__() < 2:
            raise Exception(f"bind in {self.__module__}.{WebApp.__name__}.__init__ must look like 0.0.0.0:1234")
        self.bind_ip = bind.split(':')[0]
        self.bind_port = int(bind.split(':')[1])
        self.host_url = host_url
        self.host_schema = self.host_url.split(f"://")[0]
        remain = self.host_url[self.host_schema.__len__() + 3:]
        self.host_name = remain.split('/')[0].split(':')[0]
        self.host_port = None
        self.host_api_url = self.host_url + "/" + self.api_host_dir
        if remain.split('/')[0].split(':').__len__() == 2:
            self.host_port = int(remain.split('/')[0].split(':')[1])
            remain = remain[self.host_name.__len__() + str(self.host_port).__len__() + 1:]
        self.host_dir = None
        if remain != "":
            self.host_dir = remain



        if self.static_dir is not None:
            from fastapi.staticfiles import StaticFiles
            if self.host_dir is not None and self.host_dir != "":
                self.app.mount(self.host_dir + "/static", StaticFiles(directory=self.static_dir), name="static")
            else:
                self.app.mount("/static", StaticFiles(directory=self.static_dir),
                               name="static")
        if self.template_dir is not None and self.template_dir[0:2] == "./":
            self.template_dir = os.path.join(self.working_dir, self.template_dir[2:])
        if self.template_dir is not None:
            self.templates = Jinja2Templates(directory=self.template_dir)

        self.controller_dirs = []
        for x in controller_dirs:
            if x[0:2] == "./":
                self.controller_dirs += [
                    os.path.join(self.working_dir, x[2:])
                ]
            else:
                self.controller_dirs += [x]
        for x in self.controller_dirs:
            self.load_controller_from_dir(x)
        if self.host_dir is not None and self.host_dir != "":
            self.url_get_token = self.host_dir + "/" + self.url_get_token

        self.oauth2_type = OAuth2PasswordBearerAndCookie
        self.app.post("/"+self.url_get_token)(login_for_access_token)


    def unvicorn_start(self, start_path):
        global web_application
        # for k,v in self.web_app_module.__dict__.items():
        #     if v==self:
        #        self.web_app_name=k
        run_path=f"{start_path}:web_application.app"
        if self.dev_mode:
            uvicorn.run(
                run_path,
                host=self.bind_ip,
                port=self.host_port,
                log_level="info",
                workers=8,
                lifespan='on',
                reload=self.dev_mode,
                reload_dirs=self.working_dir

            )
        else:
            uvicorn.run(
                run_path,
                host=self.bind_ip,
                port=self.host_port,
                log_level="info",
                workers=8,
                lifespan='on'

            )


def web_handler(path: str, method: str,response_model=None):

    def warpper(obj):
        import inspect
        if inspect.isclass(obj):
            return __wrapper_class__(method, obj, path)
        elif callable(obj):
            # fx= fastapi.FastAPI()
            # fx.get(response_model=)

            return __wrapper_func__(method, obj, path)

    return warpper



class OAuth2PasswordBearerAndCookie(OAuth2PasswordBearer):
    def __init__(
            self,
            token_url: str,
            jwt_secret_key: str,
            jwt_algorithm: str,
            scheme_name: Optional[str] = None,
            scopes: Optional[Dict[str, str]] = None,
            description: Optional[str] = None,
            auto_error: bool = True

    ):
        if not scopes:
            scopes = {}
        super().__init__(
            tokenUrl=token_url,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
            scopes=scopes
        )
        self.jwt_secret_key = jwt_secret_key
        self.jwt_algorithm = jwt_algorithm

    async def __call__(self, request: fastapi.Request):

        if request.cookies.get('access_token_cookie', None) is not None:
            token = request.cookies['access_token_cookie']
            try:

                ret_data = jwt.decode(token, self.jwt_secret_key,
                                      algorithms=[self.jwt_algorithm],
                                      options={"verify_signature": False},
                                      )

                setattr(request, "usernane", ret_data.get("sup"))
                setattr(request, "application_name", ret_data.get("application"))
                return token
            except jose.exceptions.ExpiredSignatureError as e:
                raise HTTPException(
                    status_code=401,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        else:
            authorization: str = request.headers.get("Authorization")
            if authorization is None:
                raise fastapi.exceptions.HTTPException(status_code=401)
            scheme, token = tuple(authorization.split(' '))
            if not authorization or scheme.lower() != "bearer":
                if self.auto_error:
                    raise HTTPException(
                        status_code=401,
                        detail="Not authenticated",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                else:
                    return None
            try:
                ret_data = jwt.decode(token,
                                      self.jwt_secret_key,
                                      algorithms=[self.jwt_algorithm],
                                      options={"verify_signature": False},
                                      )

                setattr(request, "usernane", ret_data.get("usernane"))
                setattr(request, "application", ret_data.get("application"))
            except jose.exceptions.JWTError:
                raise HTTPException(
                    status_code=401,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            except jose.exceptions.ExpiredSignatureError as e:
                raise HTTPException(
                    status_code=401,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return token


def add_controller(web_app,prefix_path: str, controller_dir):
    web_app.load_controller_from_dir(prefix_path, controller_dir)
def start_with_uvicorn():
    global web_application
    if isinstance(web_application,WebApp):
        web_application.unvicorn_start(
            f"{WebApp.__module__}"
        )
    # run_path=path.replace(os.sep,"/").replace('/','.')
    # web_app.unvicorn_start(run_path)


def load_controller_from_dir(prefix, controller_path):
    global web_application
    if isinstance(web_application,WebApp):
        web_application.load_controller_from_dir(
            prefix, controller_path
        )
def middleware():
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.app.middleware("http")
def auth():
    global web_application
    if isinstance(web_application,WebApp):
        return fastapi.Depends(web_application.get_auth())

def auth_account():
    def wrapper(fn):
        if not callable(fn):
            raise Exception(f"{fn.__name__} in {fn.__code__.co_filename} must be a function")
        if fn.__annotations__ is None:
            raise Exception(f"{fn.__name__} in {fn.__code__.co_filename} function must have 2 args username:str and passwrd:str and return dict(username:str,application:str,is_ok:bool)")
        if fn.__annotations__.get('username') is None:
            raise Exception(f"{fn.__name__} in {fn.__code__.co_filename} function must have 2 args username:str and password:str dict(username:str,application:str,is_ok:bool)")
        if fn.__annotations__.get('password') is None:
            raise Exception(f"{fn.__name__} in {fn.__code__.co_filename} function must have 2 args username:str and password:str dict(username:str,application:str,is_ok:bool)")
        global web_application
        if isinstance(web_application,WebApp):
            web_application.on_auth_user = fn
    return wrapper


def fast_api()->fastapi.FastAPI:
    global web_application
    if isinstance(web_application,WebApp):
        return web_application.app
