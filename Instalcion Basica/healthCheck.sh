
#!/bin/bash
	clear
	echo "[### Checking Interfaces ###]"
	echo
	ifconfig -s
	echo
	echo "[### Checking Diskspace ###]"
	echo
	df -h
	echo
	echo "[### Checking Connectivity and DNS ###]"
	echo
	ping -c 3 www.google.com
	echo
	echo "[### CPU & GPU Temperature ###]"
	CPU_TEMP=`cat /sys/class/thermal/thermal_zone0/temp` 
	echo "$(date) @ $(hostname)"
	echo "-------------------------------------------"
	echo "GPU => $(vcgencmd measure_temp)"
	echo "CPU => temp=$((CPU_TEMP / 1000 ))'C"
	pressEnter ;
