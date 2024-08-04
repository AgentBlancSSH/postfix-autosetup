#!/bin/bash

# Update the package list
sudo apt-get update

# Upgrade the installed packages
sudo apt-get upgrade -y

# Perform a full upgrade
sudo apt-get full-upgrade -y

# Install packages
sudo apt-get install -y python3-pip curl nano python3

echo "System update, upgrade, and installations completed!"
