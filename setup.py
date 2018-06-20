#
# Coldcard USB protocol and python support library
#

# To use this command, during dev, install and yet be able to edit the code:
#
#   pip install --editable .
#

from setuptools import setup

with open('requirements.txt') as f:
    requirements = [ln for ln in f.read().splitlines() if ln and ln[0] != '#']

with open("README.md", "r") as fh:
    long_description = fh.read()

from ckcc import __version__

setup(
    name='ckcc-protocol',
    version=__version__,
    packages=[ 'ckcc' ],
    python_requires='>3.6.0',
    install_requires=requirements,
    url='https://coldcardwallet.com',
    author='Coinkite Inc.',
    author_email='support@coinkite.com',
    description="Communicate with your Coldcard via python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    entry_points='''
        [console_scripts]
        ckcc=ckcc.cli:main
    ''',
    classifiers=[
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS :: MacOS X',
    ],
)

