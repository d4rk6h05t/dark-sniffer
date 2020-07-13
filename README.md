[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub release](https://img.shields.io/badge/release-v1.0.0-green)](https://github.com/d4rk6h05t/dark-sniffer)

# Dark-sniffer
Sniffer [ small Sniffer only TCP incoming package ] Sniffers are programs that can capture/sniff/detect packets of network traffic per packet and analyze additional note to successfully run the script you must be root or prepend the sudo command at the time of executing the script. This tool makes you think about forcing the use of https protocol instead of traditional http. In your projects.

# Disclaimer
I point out that the hacking-related material found in the github account (d4rk6h05t) is for educational and demonstration purposes only. You are responsible for your own actions.

# Requirements
The project can be used with **python3.8** for to build. However, it requires __python3.*__ as minimum.
 And  **prettytable** & **getopt** packages.
# Usage
```sh
# Don't despair if it takes longer than my algorithm is optimized, 
# Remember you have to navigate a bit to see your local traffic
# You can install keyboard package with pip or pip3
$ pip install prettytable getopt
$ sudo python darksniffer.py --help
# or also you can use
$ sudo ./darksniffer.py -h
# for convenience use the custom mode to edit all the necessary arguments
$ sudo ./darksniffer.py -c
███████╗ █████╗ ██████╗ ██╗  ██╗     ███████╗███╗  ██╗██████╗██████╗██████╗███████╗██████╗ 
██╔═══█║██╔══██╗██╔══██╗██║ ██╔╝     ██╔════╝████╗ ██║╚═██╔═╝██╔═══╝██╔═══╝██╔════╝██╔══██╗
██║   █║███████║██████╔╝█████╔╝█████╗███████╗██╔██╗██║  ██║  ██████╗██████╗█████╗  ██████╔╝
██║   █║█ ╔══██║██╔══██╗██╔═██╗╚════╝╚════██║██║╚████║  ██║  ██╔═══╝██╔═══╝██╔══╝  ██╔══██╗
███████║█ ║  ██║██║  ██║██║  ██╗     ███████║██║ ╚═██║██████╗██║    ██║    ███████╗██║  ██║
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚══════╝╚═╝   ╚═╝╚═════╝╚═╝    ╚═╝    ╚══════╝╚═╝  ╚═╝
[+] :: By: d4rk6h05t [Michani. M. De La Calleja E.]  :: An small 5n1ff3r v1.0.0

 Usage: darksniffer [option] [args]
	-f 	--file <filename>   	 Set name to JSON, CSV file where the details of the intercepted packets is stored 
	-c 	--customize         	 Customize packet capture arguments 
	-p 	--packets <amount>  	 Amount of packages to be captured 
	-e 	--empty-packet      	 Accept empty packages in the data field 
	-i 	--ip-header         	 Display the IP header struct 
	-t 	--tcp-header        	 Display the TCP header struct 
	-j 	--json-details      	 Display the data in detail 
	-h 	--help              	 Display this help and exit
	-v 	--version           	 Display version for more information

```
# Intro to Transmission Control Protocol (TCP)
The Transmission Control Protocol (TCP) is used as a a host-to-host protocol between hosts on a computer for packet switching,
communication networks and in systems interconnected between networks.
For more info you can visit [RFC 793](https://tools.ietf.org/html/rfc793) & [RFC 3168](https://tools.ietf.org/html/rfc3168)
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

# Additional remarks
This project is just a simple sniffer with many limitations, if you really want to analyze packages with more depth I recommend you to see projects like [tcpdump](https://www.tcpdump.org/) and [wireshark](https://www.wireshark.org/). 

In fact wireshark provides an API for Python to analyze packages the project is known as [PyShark](https://kiminewt.github.io/pyshark/), investigate it you may be interested.



# Author
By: d4rk6h05t (Michani. M. De La Calleja E.)

# License
----

GNU Lesser General Public License v3.0

Oh Yeah! Free Software,  it's great, enjoy!
