import cy_web
@cy_web.hanlder("post","ok")
def test_ok():
    return dict(Ok=123)