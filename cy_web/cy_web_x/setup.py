import pathlib

from setuptools import setup
from Cython.Build import cythonize
import os
build_dir = pathlib.Path(__file__).parent.__str__()

file_path=os.path.join(build_dir, f"cy_web_x.py")


setup(
    name='pyx_re_quicky_routers',
    ext_modules=cythonize(file_path),
    zip_safe=True,
)
#python3 cy_web/cy_web_x/setup.py build_ext --inplace