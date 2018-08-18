import os
import re
from setuptools import setup

base_dir = os.path.dirname(os.path.abspath(__file__))

version = None
with open(os.path.join(base_dir, "whatwg_url.py"), encoding="utf-8") as f:
    for line in f:
        match = re.search(r"^__version__\s+=\s+\"([^\"]+)\"$", line)
        if match:
            version = match.group(1)
            break
    else:
        raise ValueError("Could not find __version__ in whatwg_url.py")


def get_long_description():
    data = ""
    with open(os.path.join(base_dir, "README.md"), encoding="utf-8") as f:
        data += f.read()
    data += "\n\n"
    with open(os.path.join(base_dir, "CHANGELOG.md"), encoding="utf-8") as f:
        data += f.read()
    return data


setup(
    name="whatwg-url",
    version=version,
    description="Python implementation of the WHATWG URL Living Standard",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="Seth Michael Larson",
    author_email="sethmichaellarson@gmail.com",
    url="https://github.com/SethMichaelLarson/whatwg-url-python",
    license="Apache-2.0",
    py_modules=["whatwg_url"],
    python_requires=">=3.6",
    install_requires=["idna"],
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "License :: OSI Approved :: Apache Software License",
    ],
)
