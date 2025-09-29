from setuptools import setup, find_packages
from setuptools_rust import Binding, RustExtension

setup(
    name="py3-hessian2",
    version="0.1.0",
    rust_extensions=[RustExtension("py3_hessian2_rsimpl", binding=Binding.PyO3)],
    packages=find_packages(),
    zip_safe=False,
)