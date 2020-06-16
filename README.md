[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

# dark-sniffer
Sniffer [ small Sniffer only TCP incoming package ] Sniffers are programs that can capture/sniff/detect packets of network traffic per packet and analyze additional note to successfully run the script you must be root or prepend the sudo command at the time of executing the script. This tool makes you think about forcing the use of https protocol instead of traditional http. In your projects.

# Disclaimer
We point out that the hacking related material found in the github account (d4rk6h05t) is for educational and demonstration purposes only.
We are not responsible for any damages. You are responsible for your own actions.

# Requirements
The project can be used with **python3.8** for to build. However, it requires __python3.*__ as minimum.
 and **keyboard** package.

# Usage
```sh
# Don't despair if it takes longer than my algorithm is optimized, 
# Remember you have to navigate a bit to see your local traffic
# You can install keyboard package with pip or pip3
$ pip install keyboard
$ sudo python darksniffer.py
# or also you can use
$ sudo ./darksniffer.py
# to stop the process you must type the keyboard shortcut ctrl + c or press  several times esc to exit!
> darksnifer running ... (Wait esc key)
> Bye.
$

```
# Intro to Transmission Control Protocol (TCP)
The Transmission Control Protocol (TCP) is used as a a host-to-host protocol between hosts on a computer for packet switching,
communication networks and in systems interconnected between networks.
For more info you can visit [RFC 793](https://tools.ietf.org/html/rfc793)
The different layers of abstraction are shown below. the figures were obtained from the previously published link
                            
                            Protocol Layering

                        +---------------------+
                        |     higher-level    |
                        +---------------------+
                        |        TCP          |
                        +---------------------+
                        |  internet protocol  |
                        +---------------------+
                        |communication network|
                        +---------------------+
                        
                         Protocol Relationships 

       +------+ +-----+ +-----+       +-----+
       |Telnet| | FTP | |Voice|  ...  |     |  Application Level
       +------+ +-----+ +-----+       +-----+
             |   |         |             |
            +-----+     +-----+       +-----+
            | TCP |     | RTP |  ...  |     |  Host Level
            +-----+     +-----+       +-----+
               |           |             |
            +-------------------------------+
            |    Internet Protocol & ICMP   |  Gateway Level
            +-------------------------------+
                           |
              +---------------------------+
              |   Local Network Protocol  |    Network Level
              +---------------------------+

                         


# Author
By: Michani M. De La Calleja E. ( d4rk6h05t ) 


# License
----

GNU Lesser General Public License v3.0

Oh Yeah! Free Software,  it's great, enjoy!
