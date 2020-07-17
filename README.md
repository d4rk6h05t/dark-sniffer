[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub release](https://img.shields.io/badge/release-v1.0.0-green)](https://github.com/d4rk6h05t/dark-sniffer)

# Dark-sniffer
Sniffer [ small Sniffer only TCP/ICMP/UDP incoming package ] Sniffers are programs that can capture/sniff/detect packets of network traffic per packet and analyze additional note to successfully run the script you must be root or prepend the sudo command at the time of executing the script. This tool makes you think about forcing the use of https protocol instead of traditional http. In your projects.

# Disclaimer
I point out that the hacking-related material found in the github account (d4rk6h05t) is for educational and demonstration purposes only. You are responsible for your own actions.

# Requirements
The project can be used with **python3.8** for to build. However, it requires **python3.5** as minimum. And  **Ptable** package. 
If you don't want to install python3.8 on your main operating system, you can install python3.8 on a virtual environment you can use **virtualenv** or **pipenv**

# installation & Usage
```sh
# Don't despair if it takes longer than my algorithm is optimized, 
# Remember you have to navigate a bit to see your local traffic
# If you don't specify the number of packets, by default it only captures 5 packets
# If you don't specify the protocol, by default I cathurate only TCP packets

# clone the repository
$ git clone https://github.com/d4rk6h05t/dark-sniffer.git

# access the project directory
$ cd dark-sniffer

# If you are using virtualenv or simply want to install the package, 
# you can use either of these 2 commands, they both have the same purpose

# You can install keyboard package with pip or pip3
$ pip install PTable

# Or 
$ pip install -r requirements.txt

# Or if you are using pipfile you can install the package using the following command
$ pipenv install

# Remember,  you must be root or put the sudo command first to raise your permission level
# ready ! you can try dark-sniffer
$ sudo python darksniffer.py --help

# or also you can use
$ sudo ./darksniffer.py -h

# remember to navigate a little bit somewhere specific to speed up the capture of packets
# for convenience use the custom mode to edit all the necessary arguments
$ sudo ./darksniffer.py -c

███████╗ █████╗ ██████╗ ██╗  ██╗     ███████╗███╗  ██╗██████╗██████╗██████╗███████╗██████╗ 
██╔═══█║██╔══██╗██╔══██╗██║ ██╔╝     ██╔════╝████╗ ██║╚═██╔═╝██╔═══╝██╔═══╝██╔════╝██╔══██╗
██║   █║███████║██████╔╝█████╔╝█████╗███████╗██╔██╗██║  ██║  ██████╗██████╗█████╗  ██████╔╝
██║   █║█ ╔══██║██╔══██╗██╔═██╗╚════╝╚════██║██║╚████║  ██║  ██╔═══╝██╔═══╝██╔══╝  ██╔══██╗
███████║█ ║  ██║██║  ██║██║  ██╗     ███████║██║ ╚═██║██████╗██║    ██║    ███████╗██║  ██║
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚══════╝╚═╝   ╚═╝╚═════╝╚═╝    ╚═╝    ╚══════╝╚═╝  ╚═╝
[+] :: By: d4rk6h05t [Michani. M. De La Calleja E.]  :: An small 5n1ff3r v1.0.0
Usage: sudo ./darksniffer.py [options] [args]

Options:
  -h, --help            show this help message and exit
  -c FILENAME_CSV, --csv-file=FILENAME_CSV
                        Save details into CSV file where the details of the
                        intercepted packets
  -j FILENAME_JSON, --json-file=FILENAME_JSON
                        Save details into JSON file where the details of the
                        intercepted packets
  -i, --interactive     Customize packet capture arguments
  -p PACKETS, --packets=PACKETS
                        Amount of packages to be captured
  -P PROTOCOL, --protocol=PROTOCOL
                        Select a specific trotocol [TCP/ICMP/UDP]
  -e, --empty-packet    Accept empty packages in the data field
  -d, --details-json    Display the data in detail in JSON Format
  -v, --version         Display version for more information

```

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

# Intro to (TCP) Transmission Control Protocol 
The Transmission Control Protocol (TCP) is used as a a host-to-host protocol between hosts on a computer for packet switching,
communication networks and in systems interconnected between networks. For more info you can visit [RFC 793](https://tools.ietf.org/html/rfc793)
The different layers of abstraction are shown below. The figures were obtained from the previously published link.

              
                        TCP Header Format
     
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Intro to (ICMP) Internet Control Message Protocol
The Internet Control Message Protocol (ICMP) is a protocol based on the collection of Internet protocols.
It is used in network devices, including routers, etc. For more info you can visit [RFC 792](https://tools.ietf.org/html/rfc792)
The figures were obtained from the previously published link.

                Internet Control Message Header Format
    
     0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             unused                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    


# Intro to (UDP) User  Datagram Protocol
The User Datagram Protocol (UDP) is one of the main protocols in the Internet protocol suite.
In UDP it defines the ability to send messages, in this case called datagrams,
to other host computers on an Internet Protocol (IP) network. For more info you can visit [RFC_768](https://tools.ietf.org/html/rfc768)
The figures were obtained from the previously published link.
                        
                        User Datagram Header Format
    
                  0      7 8     15 16    23 24    31
                 +--------+--------+--------+--------+
                 |     Source      |   Destination   |
                 |      Port       |      Port       |
                 +--------+--------+--------+--------+
                 |                 |                 |
                 |     Length      |    Checksum     |
                 +--------+--------+--------+--------+
                 |                                   |
                 |          data octets ...          |
                 +-----------------------------------+

# Additional remarks
This project is just a simple sniffer with many limitations, if you really want to analyze packages with more depth I recommend you to see projects like [tcpdump](https://www.tcpdump.org/) and [wireshark](https://www.wireshark.org/). 

In fact wireshark provides an API for Python to analyze packages the project is known as [PyShark](https://kiminewt.github.io/pyshark/), investigate it you may be interested.



# Author
By: d4rk6h05t (Michani. M. De La Calleja E.)

# License
----

GNU Lesser General Public License v3.0

Oh Yeah! Free Software,  it's great, enjoy!

This program may be freely redistributed under the terms of the GNU General Public License (GLPv3).
