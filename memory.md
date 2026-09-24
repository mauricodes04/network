# Protocol reference

Reference material injected into the local-LLM prompt when analysing a conversation.

Source: https://github.com/0xKayala/Common-Protocols (GPL-3.0). Port-to-service mappings
are IANA assignments; tables reproduced here with attribution.

## TCP

| Protocol | Acronym | Port | Description |
|----------|---------|------|-------------|
| Telnet | Telnet | 23 | Remote login service |
| Secure Shell | SSH | 22 | Secure remote login service |
| Simple Network Management Protocol | SNMP | 161-162 | Manage network devices |
| Hyper Text Transfer Protocol | HTTP | 80 | Used to transfer webpages |
| Hyper Text Transfer Protocol Secure | HTTPS | 443 | Used to transfer secure webpages |
| Domain Name System | DNS | 53 | Lookup domain names |
| File Transfer Protocol | FTP | 20-21 | Used to transfer files |
| Trivial File Transfer Protocol | TFTP | 69 | Used to transfer files |
| Network Time Protocol | NTP | 123 | Synchronize computer clocks |
| Simple Mail Transfer Protocol | SMTP | 25 | Used for email transfer |
| Post Office Protocol | POP3 | 110 | Used to retrieve emails |
| Internet Message Access Protocol | IMAP | 143 | Used to access emails |
| Server Message Block | SMB | 445 | Used to transfer files |
| Network File System | NFS | 111, 2049 | Used to mount remote systems |
| Bootstrap Protocol | BOOTP | 67, 68 | Used to bootstrap computers |
| Kerberos | Kerberos | 88 | Used for authentication and authorization |
| Lightweight Directory Access Protocol | LDAP | 389 | Used for directory services |
| Remote Authentication Dial-In User Service | RADIUS | 1812, 1813 | Used for authentication and authorization |
| Dynamic Host Configuration Protocol | DHCP | 67, 68 | Used to configure IP addresses |
| Remote Desktop Protocol | RDP | 3389 | Used for remote desktop access |
| Network News Transfer Protocol | NNTP | 119 | Used to access newsgroups |
| Remote Procedure Call | RPC | 135, 137-139 | Used to call remote procedures |
| Identification Protocol | Ident | 113 | Used to identify user processes |
| Internet Control Message Protocol | ICMP | 0-255 | Used to troubleshoot network issues |
| Internet Group Management Protocol | IGMP | 0-255 | Used for multicasting |
| Oracle DB Listener | oracle-tns | 1521/1526 | Oracle database listener service |
| Ingres Lock | ingreslock | 1524 | Ingres database backdoor capability |
| Squid Web Proxy | http-proxy | 3128 | HTTP caching and forwarding proxy |
| Secure Copy Protocol | SCP | 22 | Securely copy files between systems |
| Session Initiation Protocol | SIP | 5060 | Used for VoIP sessions |
| Simple Object Access Protocol | SOAP | 80, 443 | Used for web services |
| Secure Socket Layer | SSL | 443 | Securely transfer files |
| TCP Wrappers | TCPW | 113 | Used for access control |
| Internet Security Association and Key Management Protocol | ISAKMP | 500 | Used for VPN connections |
| Microsoft SQL Server | ms-sql-s | 1433 | Client connections to SQL Server |
| Kerberized Internet Negotiation of Keys | KINK | 892 | Authentication and authorization |
| Open Shortest Path First | OSPF | 520 | Used for routing |
| Point-to-Point Tunneling Protocol | PPTP | 1723 | Used to create VPNs |
| Remote Execution | REXEC | 512 | Execute commands on remote computers |
| Remote Login | RLOGIN | 513 | Interactive shell session on remote computer |
| X Window System | X11 | 6000 | GUI for networked computers |
| Relational Database Management System | DB2 | 50000 | RDBMS for enterprise data management |

## UDP

| Protocol | Acronym | Port | Description |
|----------|---------|------|-------------|
| Domain Name System | DNS | 53 | Resolve domain names to IP addresses |
| Trivial File Transfer Protocol | TFTP | 69 | Transfer files between systems |
| Network Time Protocol | NTP | 123 | Synchronize computer clocks in network |
| Simple Network Management Protocol | SNMP | 161 | Monitor and manage network devices |
| Routing Information Protocol | RIP | 520 | Exchange routing information between routers |
| Internet Key Exchange | IKE | 500 | Internet Key Exchange |
| Bootstrap Protocol | BOOTP | 68 | Bootstrap hosts in network |
| Dynamic Host Configuration Protocol | DHCP | 67 | Assign IP addresses dynamically |
| Telnet | TELNET | 23 | Text-based remote access |
| MySQL | MySQL | 3306 | Open-source database management system |
| Terminal Server | TS | 3389 | Microsoft Windows Terminal Services |
| NetBIOS Name | netbios-ns | 137 | Resolve NetBIOS names to IP on LAN |
| Microsoft SQL Server | ms-sql-m | 1434 | SQL Server Browser service |
| Universal Plug and Play | UPnP | 1900 | Device discovery and communication |
| PostgreSQL | PGSQL | 5432 | Object-relational database management system |
| Virtual Network Computing | VNC | 5900 | Graphical desktop sharing system |
| X Window System | X11 | 6000-6063 | GUI for Unix-like systems |
| Syslog | SYSLOG | 514 | Collect and store log messages |
| Internet Relay Chat | IRC | 194 | Real-time text messaging protocol |
| OpenPGP | OpenPGP | 11371 | Encryption and signing protocol |
| Internet Protocol Security | IPsec | 500 | Secure encrypted communication |
| X Display Manager Control Protocol | XDMCP | 177 | Remote login to X11 computer |
