#!/bin/bash

## Helpers ##
check_package_installed() {
    if [ -n "$(which dpkg)" ]; then
        dpkg -s $1 &> /dev/null
    elif [ -n "$(which rpm)" ]; then
        rpm -q $1 &> /dev/null
    fi
}

install_package() {
    if [ -n "$(which apt-get)" ]; then
        sudo apt-get install -y $1
    elif [ -n "$(which yum)" ]; then
        sudo yum install -y $1
    fi
}

check_and_install_package() {
    if ! check_package_installed $1; then
        install_package $1
    fi
}

download() {
    if [ -z "$1" ]; then
        echo "download() requires a URL as first argument"
        exit 1
    fi
    if [ -z "$2" ]; then
        echo "download() requires a destination directory as second argument"
        exit 1
    fi
    if [ ! -d "$2" ]; then
        echo "$2 is not a directory"
        exit 1
    fi

    if command -v curl >/dev/null; then
        cd "$2" || (echo "Could not cd to $2" && exit 1)
        # older versions of curl don't support --output-dir
        curl -sSLO --fail --remote-name "$1"
        cd - >/dev/null || exit
    elif command -v wget >/dev/null; then
        wget -nv -P "$2" "$1"
    else
        echo "Neither curl nor wget is available, cannot download files."
        exit 1
    fi
}

default_iptables_rules() {

    ## Reset rules ##
    sudo iptables -P INPUT ACCEPT
    sudo iptables -F
    ## end Reset rules ##

    sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    ## Default iptables log rule to match our scenario ##
    sudo iptables -A INPUT -j LOG
    sudo iptables -P INPUT DROP
    sudo iptables -P FORWARD ACCEPT
    sudo iptables -P OUTPUT ACCEPT
}

default_auditd_rules() {
    rm -f /etc/audit/rules.d/*
    download https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules /etc/audit/rules.d
    echo "-a exit,always -F arch=b64 -F auid>=1000 -F auid!=-1 -S execve
-a exit,always -F arch=b32 -F auid>=1000 -F auid!=-1 -S execve" >> /etc/audit/rules.d/custom.rules
    augenrules --check && augenrules --load &> /dev/null
    systemctl kill auditd
    systemctl start auditd ## Have to kill and restart for rpm based distros
}

generate_test_account() {
    ## generate a test user account
    PASSWORD=$(openssl rand -base64 8)
    echo "username: test
password: $PASSWORD" > /root/test_account.txt
    useradd -m -p "$PASSWORD" -s /usr/bin/bash test
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

## Install packages ##
check_and_install_package nginx
systemctl start nginx

check_and_install_package ipset

check_and_install_package iptables

if [ -n "$(which dpkg)" ]; then
    check_and_install_package auditd
elif [ -n "$(which rpm)" ]; then
    check_and_install_package audit
fi


check_and_install_package curl

check_and_install_package wget
## end Install packages ##

## main ##
default_iptables_rules
default_auditd_rules
generate_test_account
## end main ##
