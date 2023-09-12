#!/bin/bash
#Constants
GOBUSTER_VERSION="3.6.0"
SSB_VERSION="0.1.1"
# This script is used to scaffold binaries to attack defender systems
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

get_arch () {
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
get_arch_gobuster() {
    case "$(uname -m)" in
        "x86_64" | "amd64")
            echo "x86_64"
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
## end of helpers ##
## Download gobuster

download_gobuster () {
	TEMP_DIR=$(mktemp -d)
	wget -qO- "https://github.com/OJ/gobuster/releases/download/v$GOBUSTER_VERSION/gobuster_Linux_$(get_arch_gobuster).tar.gz" | tar -xz -C "$TEMP_DIR"
	mv "$TEMP_DIR/gobuster" /usr/local/bin/gobuster
	rm -rf "$TEMP_DIR"
}

download_nikto () {
	TEMP_DIR=$(mktemp -d)
	cd "$TEMP_DIR"
	git clone https://github.com/sullo/nikto
	cd nikto/program
	git checkout nikto-2.5.0
	mkdir /opt/nikto
	mv -R * /opt/nikto
	ln -s /opt/nikto/nikto.pl /usr/local/bin/nikto
	sed -i 's/#EXECDIR/EXECDIR/g' /opt/nikto/nikto.conf
	cd -
	rm -rf "$TEMP_DIR"
}

download_ssb () {
	TEMP_DIR=$(mktemp -d)
	wget -qO- "https://github.com/pwnesia/ssb/releases/download/v$SSB_VERSION/ssb_$(echo $SSB_VERSION)_linux_$(get_arch).tar.gz" | tar -xz -C "$TEMP_DIR"
	mv "$TEMP_DIR/ssb" /usr/local/bin/ssb
	rm -rf "$TEMP_DIR"
}

download_wordlists () {
	mkdir /opt/wordlists
	cd /opt/wordlists
	wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt > /dev/null
	wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt > /dev/null
	wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top100.txt > /dev/null
	cd -
}

create_aliases () {
	echo "alias webscan='/usr/local/bin/gobuster dir -w /opt/wordlists/common.txt --random-agent -u \$1'" >> ~/.bashrc
	echo "alias cvescan='/usr/local/bin/nikto -h \$1'" >> ~/.bashrc
	echo "alias sshbruteforce='/usr/local/bin/ssb -w /opt/wordlists/darkweb2017-top100.txt \$1'" >> ~/.bashrc
	echo "Please run 'source ~/.bashrc' to use the aliases"
}
check_and_install_package git
download_wordlists
download_gobuster
download_nikto
download_ssb
create_aliases
