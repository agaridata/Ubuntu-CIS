Ubuntu 16.04 CIS STIG
================

# CIS-Ubuntu-Linux-16.04
Ansible role that configures Ubuntu Linux 16.04 CIS

## Requirements
Ansible 2.3+

## Role tree

defaults: The defaults directory is designated for variable defaults that take the lowest precedence. Put another way: If a variable is defined nowhere else, the definition given in defaults/main.yml will be used.

files: The files and templates directories serve a similar purpose. They contain affiliated files and Ansible templates (respectively) that are used within the role. 

handlers: The handlers directory is used to store Ansible handlers. Ansible handlers are simply tasks that may be flagged during a play to run at the play’s completion. You may have as many or as few handlers as are needed for your role.

meta: The meta directory contains authorship information

task: The task directory is where most of your role will be written. This directory includes all the tasks that your role will run. Ideally, each logically related series of tasks would be laid out in their own files, and simply included through the main.yml file in the tasks directory.

vars: This is where you create variable files that define necessary variables for your role. The variables defined in this directory are meant for role internal use only.


Role Tasks
--------------

CIS - Network settings (Section 3) tags: "section_3, scored, non_scored"

CIS - Logging and Auditing settings (Section 4) tags: "section_4, scored, non_scored"

CIS - Access, Authentication and Authorization settings (Section 5) tags: "section_5, scored, non_scored"

CIS - System Maintenance settings (Section 6) tags: "section_6, scored, non_scored"

Variables
--------------

iptables_rules_file - path where iptables rules need to be stored
role_path - will return the current role’s pathname
syslog_package - syslog package name
remote_logs_host_address - SysLog remote server hostname or ip address

Files
--------------

All files stored in the directory files required for log rotation on managed host with retention period 30 days "rotate 30". Can be decreased.

Create Playbook
-------------------

Create an empty directory CIS-Ubuntu-Linux

```
mkdir CIS-Ubuntu-Linux 
```

Switch to this directory and create a roles directory

```
cd CIS-Ubuntu-Linux ; mkdir roles
```

Switch to roles directory and clone role to it Clone role: 

```
cd roles ; git clone "repo url"
```

Switch back to root folder "CIS-Ubuntu-Linux" and create an ansible playbook:

```
cd .. ; cat >>  playbook.yml << 'EOF'
---
- hosts: all
  roles:
    - cis-ubuntu-linux-16.04
EOF
```

Create groups_vars/all to save common variables for all groups.

Example.
```
$ cat group_vars/all
ansible_user: ubuntu
ansible_python_interpreter: /usr/bin/python3
```

Create inventory file.

Example.
```
$ cat hosts
[ubuntu]
ubuntu ansible_host=1.1.1.1
```

To Run Playbook 
-------------------
Example.
```
ansible-playbook -i hosts --private-key /path/to/private/key playbook.yml -b -v
```
