#!/bin/bash
## This script just automates downloading a binary from github and run it to check if it works
## This will trigger 2 auditd scenarios
## Helpers ##

get_arch() {
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

##  End Helpers ##

wget -qO- "https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_$(get_arch).tar.gz" | tar xz -C /tmp && \
    /tmp/gobuster --help &>/dev/null