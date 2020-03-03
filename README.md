Ubuntu 16.04 CIS STIG
================

Configure Ubuntu 16.04 machine to be CIS compliant. Level 1 and 2 findings will be corrected by default.

This role **will make changes to the system** that could break things. This is not an auditing tool but rather a remediation tool to be used after an audit has been conducted.

Based on [CIS Ubuntu Benchmark v1.1.0 - 12-28-2017 ](https://www.cisecurity.org/benchmark/ubuntu_linux/). To download this guide, you will need to click the `Download Latest CIS Benchmark Guide (For Ubuntu Linus 18.04)` and register. An email with a personal download link will be sent to your registered email address. From that link you can download the Ubuntu 16.04 guide.

This repo originated from work done by [florianutz](https://github.com/florianutz/Ubuntu1604-CIS)

Requirements
------------

You should carefully read through the tasks to make sure these changes will not break your systems before running this playbook.

Role Variables
--------------
There are many role variables defined in defaults/main.yml. This list shows the most important.

**ubuntucis_notauto**: Run CIS checks that we typically do NOT want to automate due to the high probability of breaking the system (Default: false)

**ubuntucis_section1**: CIS - General Settings (Section 1) (Default: true)

**ubuntucis_section2**: CIS - Services settings (Section 2) (Default: true)

**ubuntucis_section3**: CIS - Network settings (Section 3) (Default: true)

**ubuntucis_section4**: CIS - Logging and Auditing settings (Section 4) (Default: true)

**ubuntucis_section5**: CIS - Access, Authentication and Authorization settings (Section 5) (Default: true)

**ubuntucis_section6**: CIS - System Maintenance settings (Section 6) (Default: true)

##### Disable all selinux functions
`ubuntucis_selinux_disable: false`

##### Service variables:
###### These control whether a server should or should not be allowed to continue to run these services

```
ubuntucis_avahi_server: false
ubuntucis_cups_server: false
ubuntucis_dhcp_server: false
ubuntucis_ldap_server: false
ubuntucis_telnet_server: false
ubuntucis_nfs_server: false
ubuntucis_rpc_server: false
ubuntucis_ntalk_server: false
ubuntucis_rsyncd_server: false
ubuntucis_tftp_server: false
ubuntucis_rsync_server: false
ubuntucis_nis_server: false
ubuntucis_snmp_server: false
ubuntucis_squid_server: false
ubuntucis_smb_server: false
ubuntucis_dovecot_server: false
ubuntucis_apache2_server: false
ubuntucis_vsftpd_server: false
ubuntucis_named_server: false
```

##### Designate server as a Mail server
`ubuntucis_is_mail_server: false`


##### System network parameters (host only OR host and router)
`ubuntucis_is_router: false`


##### IPv6 required
`ubuntucis_ipv6_required: true`


##### AIDE
`ubuntucis_config_aide: true`

###### AIDE cron settings
```
ubuntucis_aide_cron:
  cron_user: root
  cron_file: /etc/crontab
  aide_job: '/usr/sbin/aide --check'
  aide_minute: 0
  aide_hour: 5
  aide_day: '*'
  aide_month: '*'
  aide_weekday: '*'
```

##### SELinux policy
`ubuntucis_selinux_pol: targeted`


##### Set to 'true' if X Windows is needed in your environment
`ubuntucis_xwindows_required: no`


##### Client application requirements
```
ubuntucis_ldap_utils_required: false
ubuntucis_telnet_required: false
ubuntucis_talk_required: false
ubuntucis_rsh_required: false
ubuntucis_nis_required: false
```

##### Time Synchronization
```
ubuntucis_time_synchronization: chrony
ubuntucis_time_Synchronization: ntp

ubuntucis_time_synchronization_servers:
    - 0.pool.ntp.org
    - 1.pool.ntp.org
    - 2.pool.ntp.org
    - 3.pool.ntp.org
```

##### 3.4.2 | PATCH | Ensure /etc/hosts.allow is configured
```
ubuntucis_host_allow:
  - "10.0.0.0/255.0.0.0"
  - "172.16.0.0/255.240.0.0"
  - "192.168.0.0/255.255.0.0"
```

```
ubuntucis_firewall: firewalld
ubuntucis_firewall: iptables
```


Dependencies
------------

Ansible > 2.2

Example Playbook
-------------------------

```
- name: Harden Server
  hosts: servers
  become: yes

  roles:
    - Ubuntu1604-CIS
```

Tags
----
Many tags are available for precise control of what is and is not changed.

Some examples of using tags:

```
    # Audit and patch the site
    ansible-playbook site.yml --tags="patch"
```

License
-------

MIT
