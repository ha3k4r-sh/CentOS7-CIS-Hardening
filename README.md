# CentOS7-Hardening script for CIS

Hello There,

We all know that CentOS 7 is widely used and I did the hardening for one my Dev/QA and Prod Env. I thought this script may helps others as well.

This script  remediates 142 out of 223 security policies,

## Check the full script before using it - this may break multiple services
## Test it in Dev/QA ENV and then go for Prod
## If you face any issue - please reach me at aadham.m@outlook.com

**Policy Title : **

Disable Automounting
Ensure /etc/hosts.deny is configured
Ensure access to the su command is restricted
Ensure AIDE is installed
Ensure at/cron is restricted to authorized users
Ensure audit logs are not automatically deleted
Ensure auditd service is enabled
Ensure authentication required for single user mode
Ensure Avahi Server is not enabled
Ensure bogus ICMP responses are ignored
Ensure broadcast ICMP requests are ignored
Ensure changes to system administration scope (sudoers) is collected
Ensure chargen services are not enabled
Ensure chrony is configured
Ensure core dumps are restricted
Ensure cron daemon is enabled
Ensure CUPS is not enabled
Ensure daytime services are not enabled
Ensure DCCP is disabled
Ensure default deny firewall policy
Ensure default group for the root account is GID 0
Ensure default user shell timeout is 900 seconds or less
Ensure default user umask is 027 or more restrictive
Ensure DHCP Server is not enabled
Ensure discard services are not enabled
Ensure DNS Server is not enabled
Ensure echo services are not enabled
Ensure events that modify the system's Mandatory Access Controls are collected
Ensure filesystem integrity is regularly checked
Ensure FTP Server is not enabled
Ensure gpgcheck is globally activated
Ensure HTTP Proxy Server is not enabled
Ensure HTTP server is not enabled
Ensure ICMP redirects are not accepted
Ensure IMAP and POP3 server is not enabled
Ensure inactive password lock is 30 days or less
Ensure iptables is installed
Ensure IPv6 redirects are not accepted
Ensure IPv6 router advertisements are not accepted
Ensure LDAP client is not installed
Ensure LDAP server is not enabled
Ensure local login warning banner is configured properly
Ensure login and logout events are collected
Ensure loopback traffic is configured
Ensure mail transfer agent is configured for local-only mode
Ensure message of the day is configured properly
Ensure minimum days between password changes is 7 or more
Ensure mounting of cramfs filesystems is disabled
Ensure mounting of FAT filesystems is disabled
Ensure mounting of freevxfs filesystems is disabled
Ensure mounting of hfs filesystems is disabled
Ensure mounting of hfsplus filesystems is disabled
Ensure mounting of jffs2 filesystems is disabled
Ensure mounting of squashfs filesystems is disabled
Ensure mounting of udf filesystems is disabled
Ensure NFS and RPC are not enabled
Ensure NIS Client is not installed
Ensure NIS Server is not enabled
Ensure no legacy "+" entries exist in /etc/group
Ensure no legacy "+" entries exist in /etc/passwd
Ensure no legacy "+" entries exist in /etc/shadow
Ensure ntp is configured
Ensure outbound and established connections are configured
Ensure packet redirect sending is disabled
Ensure password expiration is 365 days or less
Ensure password expiration warning days is 7 or more
Ensure password hashing algorithm is SHA-512
Ensure password reuse is limited
Ensure permissions on /etc/cron.d are configured
Ensure permissions on /etc/cron.daily are configured
Ensure permissions on /etc/cron.hourly are configured
Ensure permissions on /etc/cron.monthly are configured
Ensure permissions on /etc/cron.weekly are configured
Ensure permissions on /etc/crontab are configured
Ensure permissions on /etc/group are configured
Ensure permissions on /etc/group- are configured
Ensure permissions on /etc/gshadow are configured
Ensure permissions on /etc/gshadow- are configured
Ensure permissions on /etc/hosts.allow are configured
Ensure permissions on /etc/hosts.deny are configured
Ensure permissions on /etc/issue are configured
Ensure permissions on /etc/issue.net are configured
Ensure permissions on /etc/motd are configured
Ensure permissions on /etc/passwd are configured
Ensure permissions on /etc/passwd- are configured
Ensure permissions on /etc/shadow are configured
Ensure permissions on /etc/shadow- are configured
Ensure permissions on /etc/ssh/sshd_config are configured
Ensure permissions on all logfiles are configured
Ensure permissions on bootloader config are configured
Ensure prelink is disabled
Ensure RDS is disabled
Ensure Reverse Path Filtering is enabled
Ensure rsh client is not installed
Ensure rsh server is not enabled
Ensure rsync service is not enabled
Ensure rsyslog default file permissions configured
Ensure rsyslog or syslog-ng is installed
Ensure rsyslog Service is enabled
Ensure Samba is not enabled
Ensure SCTP is disabled
Ensure secure ICMP redirects are not accepted
Ensure SELinux is installed
Ensure SELinux is not disabled in bootloader configuration
Ensure session initiation information is collected
Ensure SETroubleshoot is not installed
Ensure SNMP Server is not enabled
Ensure source routed packets are not accepted
Ensure SSH HostbasedAuthentication is disabled
Ensure SSH Idle Timeout Interval is configured
Ensure SSH IgnoreRhosts is enabled
Ensure SSH LoginGraceTime is set to one minute or less
Ensure SSH LogLevel is set to INFO
Ensure SSH MaxAuthTries is set to 4 or less
Ensure SSH PermitEmptyPasswords is disabled
Ensure SSH PermitUserEnvironment is disabled
Ensure SSH Protocol is set to 2
Ensure SSH root login is disabled
Ensure SSH warning banner is configured
Ensure SSH X11 forwarding is disabled
Ensure sticky bit is set on all world-writable directories
Ensure suspicious packets are logged
Ensure syslog-ng service is enabled
Ensure system accounts are non-login
Ensure system administrator actions (sudolog) are collected
Ensure system is disabled when audit logs are full
Ensure talk client is not installed
Ensure talk server is not enabled
Ensure TCP SYN Cookies is enabled
Ensure TCP Wrappers is installed
Ensure telnet client is not installed
Ensure telnet server is not enabled
Ensure tftp server is not enabled
Ensure tftp server is not enabled
Ensure the audit configuration is immutable
Ensure the MCS Translation Service (mcstrans) is not installed
Ensure time services are not enabled
Ensure time synchronization is in use
Ensure TIPC is disabled
Ensure updates, patches, and additional security software are installed
Ensure X Window System is not installed
Ensure xinetd is not enabled

**How to use the script : **

    [+] Make sure you are logged in to the virtual machine as a root user.
    [+] Open the bash terminal and download the script from GitHub using the following command:
    [+] wget 
    [+] sudo su
    [+] bash centos7hardening.sh 

