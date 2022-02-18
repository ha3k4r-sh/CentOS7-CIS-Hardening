# CentOS7-Hardening script for CIS

Hello There,

We all know that CentOS 7 is widely used and I did the hardening for one my Dev/QA and Prod Env. I thought this script may helps others as well.

This script  remediates 142 out of 223 security policies,

Check the full script before using it - this may break multiple services
Test it in Dev/QA ENV and then go for Prod
If you face any issue - please reach me at aadham.m@outlook.com

**Policy Title : **


S.No  | Control
------------- | -------------
1	| Disable Automounting
2	| Ensure /etc/hosts.deny is configured
3	| Ensure access to the su command is restricted
4	| Ensure AIDE is installed
5	| Ensure at/cron is restricted to authorized users
6	| Ensure audit logs are not automatically deleted
7	| Ensure auditd service is enabled
8	| Ensure authentication required for single user mode
9	| Ensure Avahi Server is not enabled
10	| Ensure bogus ICMP responses are ignored
11	| Ensure broadcast ICMP requests are ignored
12	| Ensure changes to system administration scope (sudoers) is collected
13	| Ensure chargen services are not enabled
14	| Ensure chrony is configured
15	| Ensure core dumps are restricted
16	| Ensure cron daemon is enabled
17	| Ensure CUPS is not enabled
18	| Ensure daytime services are not enabled
19	| Ensure DCCP is disabled
20	| Ensure default deny firewall policy
21	| Ensure default group for the root account is GID 0
22	| Ensure default user shell timeout is 900 seconds or less
23	| Ensure default user umask is 027 or more restrictive
24	| Ensure DHCP Server is not enabled
25	| Ensure discard services are not enabled
26	| Ensure DNS Server is not enabled
27	| Ensure echo services are not enabled
28	| Ensure events that modify the system's Mandatory Access Controls are collected
29	| Ensure filesystem integrity is regularly checked
30	| Ensure FTP Server is not enabled
31	| Ensure gpgcheck is globally activated
32	| Ensure HTTP Proxy Server is not enabled
33	| Ensure HTTP server is not enabled
34	| Ensure ICMP redirects are not accepted
35	| Ensure IMAP and POP3 server is not enabled
36	| Ensure inactive password lock is 30 days or less
37	| Ensure iptables is installed
38	| Ensure IPv6 redirects are not accepted
39	| Ensure IPv6 router advertisements are not accepted
40	| Ensure LDAP client is not installed
41	| Ensure LDAP server is not enabled
42	| Ensure local login warning banner is configured properly
43	| Ensure login and logout events are collected
44	| Ensure loopback traffic is configured
45	| Ensure mail transfer agent is configured for local-only mode
46	| Ensure message of the day is configured properly
47	| Ensure minimum days between password changes is 7 or more
48	| Ensure mounting of cramfs filesystems is disabled
49	| Ensure mounting of FAT filesystems is disabled
50	| Ensure mounting of freevxfs filesystems is disabled
51	| Ensure mounting of hfs filesystems is disabled
52	| Ensure mounting of hfsplus filesystems is disabled
53	| Ensure mounting of jffs2 filesystems is disabled
54	| Ensure mounting of squashfs filesystems is disabled
55	| Ensure mounting of udf filesystems is disabled
56	| Ensure NFS and RPC are not enabled
57	| Ensure NIS Client is not installed
58	| Ensure NIS Server is not enabled
59	| Ensure no legacy "+" entries exist in /etc/group
60	| Ensure no legacy "+" entries exist in /etc/passwd
61	| Ensure no legacy "+" entries exist in /etc/shadow
62	| Ensure ntp is configured
63	| Ensure outbound and established connections are configured
64	| Ensure packet redirect sending is disabled
65	| Ensure password expiration is 365 days or less
66	| Ensure password expiration warning days is 7 or more
67	| Ensure password hashing algorithm is SHA-512
68	| Ensure password reuse is limited
69	| Ensure permissions on /etc/cron.d are configured
70	| Ensure permissions on /etc/cron.daily are configured
71	| Ensure permissions on /etc/cron.hourly are configured
72	| Ensure permissions on /etc/cron.monthly are configured
73	| Ensure permissions on /etc/cron.weekly are configured
74	| Ensure permissions on /etc/crontab are configured
75	| Ensure permissions on /etc/group are configured
76	| Ensure permissions on /etc/group- are configured
77	| Ensure permissions on /etc/gshadow are configured
78	| Ensure permissions on /etc/gshadow- are configured
79	| Ensure permissions on /etc/hosts.allow are configured
80	| Ensure permissions on /etc/hosts.deny are configured
81	| Ensure permissions on /etc/issue are configured
82	| Ensure permissions on /etc/issue.net are configured
83	| Ensure permissions on /etc/motd are configured
84	| Ensure permissions on /etc/passwd are configured
85	| Ensure permissions on /etc/passwd- are configured
86	| Ensure permissions on /etc/shadow are configured
87	| Ensure permissions on /etc/shadow- are configured
88	| Ensure permissions on /etc/ssh/sshd_config are configured
89	| Ensure permissions on all logfiles are configured
90	| Ensure permissions on bootloader config are configured
91	| Ensure prelink is disabled
92	| Ensure RDS is disabled
93	| Ensure Reverse Path Filtering is enabled
94	| Ensure rsh client is not installed
95	| Ensure rsh server is not enabled
96	| Ensure rsync service is not enabled
97	| Ensure rsyslog default file permissions configured
98	| Ensure rsyslog or syslog-ng is installed
99	| Ensure rsyslog Service is enabled
100	| Ensure Samba is not enabled
101	| Ensure SCTP is disabled
102	| Ensure secure ICMP redirects are not accepted
103	| Ensure SELinux is installed
104	| Ensure SELinux is not disabled in bootloader configuration
105	| Ensure session initiation information is collected
106	| Ensure SETroubleshoot is not installed
107	| Ensure SNMP Server is not enabled
108	| Ensure source routed packets are not accepted
109	| Ensure SSH HostbasedAuthentication is disabled
110	| Ensure SSH Idle Timeout Interval is configured
111	| Ensure SSH IgnoreRhosts is enabled
112	| Ensure SSH LoginGraceTime is set to one minute or less
113	| Ensure SSH LogLevel is set to INFO
114	| Ensure SSH MaxAuthTries is set to 4 or less
115	| Ensure SSH PermitEmptyPasswords is disabled
116	| Ensure SSH PermitUserEnvironment is disabled
117	| Ensure SSH Protocol is set to 2
118	| Ensure SSH root login is disabled
119	| Ensure SSH warning banner is configured
120	| Ensure SSH X11 forwarding is disabled
121	| Ensure sticky bit is set on all world-writable directories
122	| Ensure suspicious packets are logged
123	| Ensure syslog-ng service is enabled
124	| Ensure system accounts are non-login
125	| Ensure system administrator actions (sudolog) are collected
126	| Ensure system is disabled when audit logs are full
127	| Ensure talk client is not installed
128	| Ensure talk server is not enabled
129	| Ensure TCP SYN Cookies is enabled
130	| Ensure TCP Wrappers is installed
131	| Ensure telnet client is not installed
132	| Ensure telnet server is not enabled
133	| Ensure tftp server is not enabled
134	| Ensure tftp server is not enabled
135	| Ensure the audit configuration is immutable
136	| Ensure the MCS Translation Service (mcstrans) is not installed
137	| Ensure time services are not enabled
138	| Ensure time synchronization is in use
139	| Ensure TIPC is disabled
140	| Ensure updates, patches, and additional security software are installed
141	| Ensure X Window System is not installed
142	| Ensure xinetd is not enabled


**How to use the script : **

    [+] Make sure you are logged in to the virtual machine as a root user.
    [+] Open the bash terminal and download the script from GitHub using the following command:
    
    wget https://raw.githubusercontent.com/ha3k4r-sh/CentOS7-CIS-Hardening/main/centos7_hardening.sh
    sudo su
    bash centos7_hardening.sh 

