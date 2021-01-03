from setuptools import setup, find_packages

setup(
    name='ntlm',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'pycryptodome',
        'msdsalgs @ git+ssh://git@github.com/vphpersson/msdsalgs.git#egg=msdsalgs',
    ]
)
