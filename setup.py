from setuptools import setup, find_packages

setup(
    name='ntlm',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'pycryptodome @ https://github.com/Legrandin/pycryptodome/targball/master',
        'msdsalgs @ https://github.com/vphpersson/msdsalgs/tarball/master'
    ]
)
