#!/bin/bash

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

echo "Creating namespaces ..."
# Create virtual bridges
sudo ip link add vbr1 type bridge
sudo ip link add vbr2 type bridge

# Create namespaces
sudo ip netns add ns1
sudo ip netns add ns2

# Create virtual links
sudo ip link add v1 type veth peer name v1br1
sudo ip link add v2 type veth peer name v2br2
sudo ip link add v3 type veth peer name v4

# Connect bridges & namespaces using these links
sudo ip link set v1 netns ns1
sudo ip link set v2 netns ns2
sudo ip link set v1br1 master vbr1
sudo ip link set v2br2 master vbr2
sudo ip link set v3 master vbr1
sudo ip link set v4 master vbr2

# Add ip addresses to bridges & bring them up
sudo ip link set dev vbr1 up
sudo ip link set dev vbr2 up
sudo ip addr add 10.0.0.5/24 dev vbr1
sudo ip addr add 10.0.0.9/24 dev vbr2
sudo ip link set v1br1 up
sudo ip link set v2br2 up
sudo ip link set v3 up
sudo ip link set v4 up

# Setup IP and set the links up
sudo ip netns exec ns1 ip addr add 10.0.0.1/24 dev v1
sudo ip netns exec ns2 ip addr add 10.0.0.2/24 dev v2
sudo ip netns exec ns1 ip link set lo up
sudo ip netns exec ns2 ip link set lo up
sudo ip netns exec ns1 ip link set v1 up
sudo ip netns exec ns2 ip link set v2 up

echo ""
echo "Created these Linux network namespaces:"
echo "Turning offloading off"
sudo ip netns exec ns1 ethtool -K v1 rx off tx off
sudo ip netns exec ns2 ethtool -K v2 rx off tx off
sudo ethtool -K v3 rx off tx off
sudo ethtool -K v4 rx off tx off

sudo ip netns exec ns1 ip route del 10.0.0.0/24 dev v1
sudo ip netns exec ns1 ip route add 10.0.0.0/24 dev v1 advmss 1424
sudo ip netns exec ns2 ip route del 10.0.0.0/24 dev v2
sudo ip netns exec ns2 ip route add 10.0.0.0/24 dev v2 advmss 1424
echo ""

echo ""
echo "+-------------------+ +-----------------------------------------+"
echo "| namespace ns1     | |                default namespace        |"
echo "|                   | |                                         |"
echo "|       10.0.0.1/24 | |   (interface)                           |"
echo "|            v1 --------- v1br1 -------- vbr1 (software bridge) |"
echo "|       (interface) | |                   |   10.0.0.5/24       |"
echo "+-------------------+ |                   |                     |"
echo "                      |                  v3 (interface)         |"
echo "                      |                   |                     |"
echo "|-------------------+ |                   |                     |"
echo "| namespace ns2     | |                  v4 (interface)         |"
echo "|                   | |                   |                     |"
echo "|       10.0.0.2/24 | |                   |                     |"
echo "|            v2 --------- v2br2 -------- vbr2 (software bridge) |"
echo "|       (interface) | |   (interface)         10.0.0.9/24       |"
echo "+-------------------+ +-----------------------------------------+"
echo ""
echo "To start a shell in ns1 / ns2:"
echo "    sudo ip netns exec ns1 bash"
echo "    sudo ip netns exec ns2 bash"
echo ""
echo "Useful tcpdump options to see packets on v1 (v2) run from inside ns1 (ns2):"
echo "    tcpdump -l -X -vv -i v1"
echo "    tcpdump -l -X -vv -i v2"
