from setuptools import setup, find_packages

setup(
    name='ntlm',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'pycryptodome',
        'msdsalgs @ https://github.com/vphpersson/msdsalgs/tarball/master'
    ]
)
