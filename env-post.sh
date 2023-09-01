#!/bin/bash

## Helpers ##
restart_crowdsec_service() {
    if systemctl is-active --quiet crowdsec; then
        systemctl restart crowdsec
    fi
}

install_package() {
    if [ -n "$(which apt-get)" ]; then
        sudo apt-get install -y $1
    elif [ -n "$(which yum)" ]; then
        sudo yum install -y $1
    fi
}

get_arch() {
    case "$(uname -m)" in
        "x86_64" | "amd64")
            echo "amd64"
            ;;
        "armv7" | "armv7l")
            echo "armhf"
            ;;
        "armv8" | "aarch64")
            echo "arm64"
            ;;
        *)
            echo "Unsupported architecture"
            exit 1
            ;;
    esac
}


configure_database() {
    echo "updating config.yaml.local..."
    cat <<-EOT > "/etc/crowdsec/config.yaml.local"
	db_config:
	  use_wal: true
	EOT
}

enroll_instance_to_app() {
    if [ -n "$CONSOLE_ENROLL" ]; then
    	cscli console enroll "$CONSOLE_ENROLL"
    fi
}

set_feature_flags() {
    echo "Setting feature flags..."
    cat <<-EOT > "/etc/crowdsec/feature.yaml"
    - papi_client
	EOT
}

set_all_console_features_on() {
    echo "Setting all console features on..."
    cscli console enable --all
}

set_ssh_successful() {
    ## enable ssh password auth
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
    ## add tempban group to unix system
    groupadd tempban
    ## Inform sshd that any users in tempban cannot login
    echo "DenyGroups tempban" >> /etc/ssh/sshd_config
    ## restart sshd
    systemctl restart sshd
    ## create a scenario
    cat <<-EOT > "/etc/crowdsec/scenarios/ssh-impossible-travel-username.yaml"
type: conditional
name: crowdsecurity/ssh-impossible-travel-username
description: "ssh impossible travel"
filter: "evt.Meta.service == 'ssh' && evt.Meta.log_type == 'ssh_success-auth'"
groupby: evt.Meta.target_user
capacity: -1
condition: |
    len(queue.Queue) >= 2 
    and Distance(queue.Queue[-1].Enriched.Latitude, queue.Queue[-1].Enriched.Longitude,
    queue.Queue[-2].Enriched.Latitude, queue.Queue[-2].Enriched.Longitude) > 1000
leakspeed: 3h
reprocess: true
scope:
    type: username
    expression: evt.Meta.target_user
labels:
    type: "inside-threat"
    remediation: true
	EOT
    cat <<-EOT > "/etc/crowdsec/scenarios/ssh-impossible-travel.yaml"
type: conditional
name: crowdsecurity/ssh-impossible-travel
description: "ssh impossible travel"
filter: "evt.Meta.service == 'ssh' && evt.Meta.log_type == 'ssh_success-auth'"
groupby: evt.Meta.target_user
capacity: -1
condition: |
    len(queue.Queue) >= 2 
    and Distance(queue.Queue[-1].Enriched.Latitude, queue.Queue[-1].Enriched.Longitude,
    queue.Queue[-2].Enriched.Latitude, queue.Queue[-2].Enriched.Longitude) > 1000
leakspeed: 3h
reprocess: true
labels:
    type: "inside-threat"
    remediation: true
	EOT
    ## use custom ssh parser
    cat <<-EOT > "/etc/crowdsec/parsers/s01-parse/sshd-logs.yaml"
onsuccess: next_stage
#debug: true
filter: "evt.Parsed.program == 'sshd'"
name: crowdsecurity/sshd-logs
description: "Parse openSSH logs"
pattern_syntax:
    # The IP grok pattern that ships with crowdsec is buggy and does not capture the last digit of an IP if it is the last thing it matches, and the last octet starts with a 2
    # https://github.com/crowdsecurity/crowdsec/issues/938
    IPv4_WORKAROUND: (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
    IP_WORKAROUND: (?:%{IPV6}|%{IPv4_WORKAROUND})
    SSHD_AUTH_FAIL: 'pam_%{DATA:pam_type}\(sshd:auth\): authentication failure; logname= uid=%{NUMBER:uid}? euid=%{NUMBER:euid}? tty=ssh ruser= rhost=%{IP_WORKAROUND:sshd_client_ip}( %{SPACE}user=%{USERNAME:sshd_invalid_user})?'
    SSHD_MAGIC_VALUE_FAILED: 'Magic value check failed \(\d+\) on obfuscated handshake from %{IP_WORKAROUND:sshd_client_ip} port \d+'
    SSHD_INVALID_USER: 'Invalid user\s*%{USERNAME:sshd_invalid_user}? from %{IP_WORKAROUND:sshd_client_ip}( port \d+)?'
    SSHD_INVALID_BANNER: 'banner exchange: Connection from %{IP_WORKAROUND:sshd_client_ip} port \d+: invalid format'
    SSHD_PREAUTH_AUTHENTICATING_USER: 'Connection closed by (authenticating|invalid) user %{USERNAME:sshd_invalid_user} %{IP_WORKAROUND:sshd_client_ip} port \d+ \[preauth\]'
    #following: https://github.com/crowdsecurity/crowdsec/issues/1201 - some scanners behave differently and trigger this one
    SSHD_PREAUTH_AUTHENTICATING_USER_ALT: 'Disconnected from (authenticating|invalid) user %{USERNAME:sshd_invalid_user} %{IP_WORKAROUND:sshd_client_ip} port \d+ \[preauth\]'
    SSHD_BAD_KEY_NEGOTIATION: 'Unable to negotiate with %{IP_WORKAROUND:sshd_client_ip} port \d+: no matching (host key type|key exchange method) found.'
nodes:
    - grok:
        name: "SSHD_FAIL"
        apply_on: message
        statics:
          - meta: log_type
            value: ssh_failed-auth
          - meta: target_user
            expression: "evt.Parsed.sshd_invalid_user"
    - grok:
        name: "SSHD_PREAUTH_AUTHENTICATING_USER_ALT"
        apply_on: message
        statics:
          - meta: log_type
            value: ssh_failed-auth
          - meta: target_user
            expression: "evt.Parsed.sshd_invalid_user"
    - grok:
        name: "SSHD_PREAUTH_AUTHENTICATING_USER"
        apply_on: message
        statics:
          - meta: log_type
            value: ssh_failed-auth
          - meta: target_user
            expression: "evt.Parsed.sshd_invalid_user"
    - grok:
        name: "SSHD_DISC_PREAUTH"
        apply_on: message
    - grok:
        name: "SSHD_BAD_VERSION"
        apply_on: message
    - grok:
        name: "SSHD_INVALID_USER"
        apply_on: message
        statics:
          - meta: log_type
            value: ssh_failed-auth
          - meta: target_user
            expression: "evt.Parsed.sshd_invalid_user"
    - grok:
        name: "SSHD_INVALID_BANNER"
        apply_on: message
        statics:
          - meta: log_type
            value: ssh_failed-auth
          - meta: extra_log_type
            value: ssh_bad_banner
    - grok:
        name: "SSHD_USER_FAIL"
        apply_on: message
        statics:
          - meta: log_type
            value: ssh_failed-auth
          - meta: target_user
            expression: "evt.Parsed.sshd_invalid_user"
    - grok: 
        name: "SSHD_AUTH_FAIL"
        apply_on: message
        statics:
          - meta: log_type
            value: ssh_failed-auth
          - meta: target_user
            expression: "evt.Parsed.sshd_invalid_user"
    - grok: 
        name: "SSHD_MAGIC_VALUE_FAILED"
        apply_on: message
        statics:
          - meta: log_type
            value: ssh_failed-auth
          - meta: target_user
            expression: "evt.Parsed.sshd_invalid_user"
    - grok:
        name: "SSHD_BAD_KEY_NEGOTIATION"
        apply_on: message
        statics:
          - meta: log_type
            value: ssh_bad_keyexchange
    - grok:
        pattern: 'Accepted password for %{USERNAME:sshd_valid_user} from %{IP_WORKAROUND:sshd_client_ip} port \d+'
        apply_on: message
        statics:
          - meta: log_type
            value: ssh_success-auth
          - meta: target_user
            expression: "evt.Parsed.sshd_valid_user"
statics:
  - meta: service
    value: ssh
  - meta: source_ip
    expression: "evt.Parsed.sshd_client_ip"
	EOT
    insert_username_profile
}

insert_username_profile() {
    cat <<-EOT > "/etc/crowdsec/profiles.yaml.local"
name: username_temp_ban
filters:
 - 'Alert.Remediation == true && Alert.GetScope() == "username"'
decisions:
  - type: tempban
    scope: "username"
    duration: 12h
on_success: break
	EOT
}

insert_captcha_remediation() {
    OLD_PROFILE=$(cat /etc/crowdsec/profiles.yaml)
    cat <<-EOT > "/etc/crowdsec/profiles.yaml"
name: captcha
filters:
 - 'Alert.Remediation == true && Alert.GetScope() == "Ip" && Alert.GetScenario() contains "http"'
decisions:
  - type: captcha
    duration: 4h
on_success: break
---
$OLD_PROFILE
	EOT
}

install_custom_bouncer() {
    install_package crowdsec-custom-bouncer

    ## Patch custom-bouncer-binary scopes is only supported > 17##
    wget -qO- "https://github.com/crowdsecurity/cs-custom-bouncer/releases/download/v0.0.17-rc5/crowdsec-custom-bouncer-linux-$(get_arch).tgz" | tar -xz -C /tmp
    cd /tmp/crowdsec-custom-bouncer*/ || exit
    mv crowdsec-custom-bouncer "$(which crowdsec-custom-bouncer)"
    cd - >/dev/null || exit
    ## end Patch custom-bouncer-binary ##

    sed -i 's/bin_path/#bin_path/g' /etc/crowdsec/bouncers/crowdsec-custom-bouncer.yaml
    echo "bin_path: /opt/bouncer.sh" >> /etc/crowdsec/bouncers/crowdsec-custom-bouncer.yaml
    sed -i 's/scenarios_containing: \[\]/scenarios_containing: \["ssh-impossible-travel-username"\]/g' /etc/crowdsec/bouncers/crowdsec-custom-bouncer.yaml
    echo "scopes: [\"username\"]" >> /etc/crowdsec/bouncers/crowdsec-custom-bouncer.yaml
    cat <<-EOT > "/opt/bouncer.sh"
#!/bin/sh
if [ \$1 = "add" ]; then
    usermod -a -G tempban \$2
else
    gpasswd --delete \$2 tempban
fi
	EOT
    chmod  700 /opt/bouncer.sh
    if command -v getenforce >/dev/null; then
      if [ "$(getenforce)" == "Enforcing" ]; then
        echo "Selinux enabled, disabling due to custom bouncer"
        setenforce 0
      fi
    fi
    systemctl enable --now crowdsec-custom-bouncer
}

install_firewall_bouncer() {
    cscli collections install crowdsecurity/iptables &> /dev/null
    install_package crowdsec-firewall-bouncer-iptables
}

install_nginx_bouncer() {
    cscli collections install crowdsecurity/nginx &> /dev/null
    install_package crowdsec-nginx-bouncer
    insert_captcha_remediation
}

auditd_acquisition () {
  cscli collections install crowdsecurity/auditd &> /dev/null
  mkdir -p /etc/crowdsec/acquis.d/
      cat <<-EOT > "/etc/crowdsec/acquis.d/auditd.yaml"
filenames:
  - /var/log/audit/audit.log
labels:
  type: auditd
	EOT
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
}
## end Helpers ##

## check if script is run as root ##
check_root
## end check if script is run as root ##

## main ##
configure_database
enroll_instance_to_app
set_ssh_successful
set_feature_flags
set_all_console_features_on
install_firewall_bouncer
install_nginx_bouncer
install_custom_bouncer
auditd_acquisition


if [ -n "$CONSOLE_ENROLL" ]; then
    read -p "Press enter to continue once you have accepted the enrollment request in the console..."
fi
restart_crowdsec_service
## end main ##