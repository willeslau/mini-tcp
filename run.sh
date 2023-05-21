#!/bin/bash

# permission grant
sudo setcap CAP_NET_ADMIN=eip ./target/release/mini-tcp

# assign ip addr
ip addr add 192.167.1.0/24 dev mini-tcp-tun

# link
sudo ip link set up dev mini-tcp-tun
