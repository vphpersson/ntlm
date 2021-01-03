from setuptools import setup, find_packages

setup(
    name='ntlm',
    packages=find_packages(),
    install_requires=[
        'pycryptodome',
        'msdsalgs @ git+ssh://git@github.com/vphpersson/msdsalgs.git#egg=msdsalgs',
    ]
)
