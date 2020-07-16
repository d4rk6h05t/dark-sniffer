#!/usr/bin/env python3

from distutils.core import setup

LONG_DESCRIPTION = '''Sniffer [ small Sniffer only TCP/ICPM/UDP incoming package ] Sniffers are programs that can capture/sniff/detect packets of network traffic per packet and analyze additional note to successfully run the script you must be root or prepend the sudo command at the time of executing the script. This tool makes you think about forcing the use of https protocol instead of traditional http. In your projects.'''

setup(
    name = 'darksniffer',
    version = '1.0.0',
    description = 'Dark Sniffer - small Sniffer only TCP/ICPM/UDP incoming package ',
    long_description = LONG_DESCRIPTION,
    author = 'd4rk6h05t [ Michani M. De La Calleja E. ]',
    author_email = 'd4rk6h05t_0d4y5@protonmail.ch',
    url = 'https://github.com/d4rk6h05t/dark-sniffer',
    packages = ['darksniffer',],
    classifiers = [
        'Topic :: Security :: Networking :: Sockets :: TCP :: ICMP :: UDP ',
        'License :: GPLv3 License',
    ],
    license = 'License :: GNU Lesser General Public License v3.0 :: GPLv3 License',
)
