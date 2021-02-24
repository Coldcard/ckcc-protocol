#
# Coldcard USB protocol and python support library
#

# To use this command, during dev, install and yet be able to edit the code:
#
#   pip install --editable .
#

from setuptools import setup

requirements = [
    'hidapi>=0.7.99.post21',
    'ecdsa>=0.13',
    'pyaes',
]

cli_requirements = [
    'click>=6.7',
]

with open("README.md", "r") as fh:
    long_description = fh.read()

from ckcc import __version__

setup(
    name='ckcc-protocol',
    version=__version__,
    packages=[ 'ckcc' ],
    python_requires='>3.6.0',
    install_requires=requirements,
    extras_require={
        'cli': cli_requirements,
    },
    url='https://github.com/Coldcard/ckcc-protocol',
    author='Coinkite Inc.',
    author_email='support@coinkite.com',
    description="Communicate with your Coldcard using Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    entry_points='''
        [console_scripts]
        ckcc=ckcc.cli:main
    ''',
    classifiers=[
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS :: MacOS X',
    ],
)

