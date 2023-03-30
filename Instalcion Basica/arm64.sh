#!/bin/bash
clear ; echo "[Adding arm64 architecture...]";
sudo rpi-update
if ! grep "arm_64bit=1" "/boot/config.txt"; then echo "arm_64bit=1" | sudo tee -a /boot/config.txt; fi
sudo dpkg --add-architecture arm64
apt update -y
apt upgrade -y
#setupRepo ;
#sudo apt -y install ntp
#installCorelight
#echo "[Success] Need to reboot. [Press Enter to reboot.]" ; read DUMMY ;
sudo reboot
