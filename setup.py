from setuptools import setup, find_packages

setup(
    name='ntlm',
    version='0.9.16',
    url='https://github.com/vphpersson/ntlm',
    author='vph',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'Programming Language :: Python :: 3.7',
    ],
    packages=find_packages(),
    install_requires=['pycryptodome'],
    python_requires='>=3.7'
)
