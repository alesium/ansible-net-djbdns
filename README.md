net-djbdns
=========

Ansible Role to configure djbdns from pkgsrc

Requirements
------------

- Hosts requires pkgsrc's pkgin
- Hosts should be bootstrapped for ansible usage (have python,...)
- Root privileges, eg `become: yes`

Role Variables
--------------

| Variable | Description | Default value |
|----------|-------------|---------------|
| `net_djbdns_tinydns_conf_exec` | Location for tinydns-conf | `"/opt/local/bin/tinydns-conf"` | 
| `net_djbdns_tinydns_username` | Username tinydns should run as | `"tinydns"` | 
| `net_djbdns_tinydns_dnslog_username` | Username for dnslog | `"dnslog"` | 
| `net_djbdns_tinydns_root_dir` | Root dir when initializing tinydns | `"/var/db/tinydns"` | 
| `net_djbdns_tinydns_data_file_src` | Local location of the data file | `"data"` | 
| `net_djbdns_tinydns_data_file_dest` | Destination of the data file | `"net_djbdns_tinydns_data_file_dest"` | 
| `net_djbdns_tinydns_listen_ip_address` | IP Address to listen too | `"127.0.0.1"` | 
| `net_djbdns_tinydns_pid_file` | PID File for tinydns | `"/var/run/tinydns.pid"` | 
| `net_djbdns_tinydns_service_name` | Service name  | `"pkgsrc/tinydns"` | 
| `net_djbdns_tinydns_SmartOS_service_bundle_name` | bundle name | `"tinydns"` | 
| `net_djbdns_tinydns_SmartOS_service_exec_file` | smf exec file | `"/opt/local/lib/svc/method/tinydns-svc"` | 
| `net_djbdns_tinydns_SmartOS_service_smf_file` | smf method file | `"/opt/local/lib/svc/manifest/tinydns.xml"` | 

Dependencies
------------

None

Example Playbook
----------------


    - hosts: servers
      roles:
         - { role: sebasp.net-djbdns }

License
-------

BSD

Author Information
------------------

Sebastien Perreault <sperreault@alesium.net>
