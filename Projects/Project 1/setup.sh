#!/bin/bash

sudo apt-get update
sudo apt-get install -y binutils-dev
sudo apt-get install -y elfutils
sudo apt-get install -y libelf-dev
sudo apt-get remove -y librust-capstone-dev
sudo apt-get install -y libcapstone-dev