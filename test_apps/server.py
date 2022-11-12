from datetime import time

import fastapi

import cy_web
cy_web.create_web_app(
    working_dir= r"C:\code\python\cy_web\test_apps",
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

if __name__ =="__main__":
    cy_web.start_with_uvicorn()
