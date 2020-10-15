#!/usr/bin/env python3

#   Author: Copyright (C) 2020 Michani. M. De La Calleja E. [ d4rk6h05t ~тёмный призрак ]

from distutils.core import setup

LONG_DESCRIPTION = """Sniffer [ small Sniffer only TCP/ICPM/UDP incoming package ] Sniffers are programs that can capture/sniff/detect packets of network traffic per packet and analyze additional note to successfully run the script you must be root or prepend the sudo command at the time of executing the script. This tool makes you think about forcing the use of https protocol instead of traditional http. In your projects. Aditional Note: By default it only captures 5 packets and by default I cathurate only TCP packets""".strip()

SHORT_DESCRIPTION = """Dark Sniffer - small Sniffer only TCP/ICPM/UDP incoming package""".strip()

DEPENDENCIES = [
    'PTable'
]

TEST_DEPENDENCIES = []

setup(
    name = 'darksniffer',
    version = '1.0.0',
    description = SHORT_DESCRIPTION,
    long_description = LONG_DESCRIPTION,
    author = 'Michani M. De La Calleja E.',
    author_email = 'd4rk6h05t_0d4y5@protonmail.ch',
    url = 'https://github.com/d4rk6h05t/dark-sniffer',
    packages = ['darksniffer',],
    license = 'License :: GNU Lesser General Public License v3.0 :: GPLv3 License',
    classifiers = [
        'Topic :: Security :: Networking :: Sockets :: TCP :: ICMP :: UDP ',
        'License :: GPLv3 License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Operating System :: POSIX',
        'Operating System :: MacOS',
        'Operating System :: Unix',
    ],
)
