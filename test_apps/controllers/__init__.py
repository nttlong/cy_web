import cy_web
@cy_web.hanlder("post","ok")
def test_ok(auth=cy_web.auth()):
    return dict(Ok=123)