import os
from setuptools import setup, find_packages

base_dir = os.path.dirname(os.path.abspath(__file__))


def get_long_description():
    data = ""
    with open(os.path.join(base_dir, "README.md")) as f:
        data += f.read()
    data += "\n\n"
    with open(os.path.join(base_dir, "CHANGELOG.md")) as f:
        data += f.read()
    return data


setup(
    name="whatwg-url",
    version="2018.8.2",
    description="Python implementation of the WHATWG URL Living Standard",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="Seth Michael Larson",
    author_email="sethmichaellarson@gmail.com",
    url="https://github.com/SethMichaelLarson/whatwg-url-python",
    license="Apache-2.0",
    packages=find_packages("./src"),
    python_requires=">=3.6",
    install_requires=["attrs", "idna"],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
    ],
)
