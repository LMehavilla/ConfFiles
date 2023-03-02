cd /root
mkdir scripts
cd scripts
curl -L -O  https://raw.githubusercontent.com/HybridNetworks/whatsapp-cidr/main/WhatsApp/whatsapp_cidr_ipv4.txt
curl -L  -O https://raw.githubusercontent.com/LMehavilla/ConfFiles/main/preprocess.py

curl -L -O  https://raw.githubusercontent.com/LMehavilla/ConfFiles/main/was_machine_broker_ip.zeek
mkdir /usr/local/zeek/share/zeek/policy/custom-scripts
cp was_machine_broker_ip.zeek /usr/local/zeek/share/zeek/policy/custom-scripts/

curl -L -O  https://raw.githubusercontent.com/LMehavilla/ConfFiles/main/local.zeek 
cp local.zeek /usr/local/zeek/share/zeek/site/

curl -L -O  https://raw.githubusercontent.com/LMehavilla/ConfFiles/main/node.cfg
cp node.cfg /usr/local/zeek/etc/

curl -L -O  https://raw.githubusercontent.com/LMehavilla/ConfFiles/main/zeekctl.cfg
cp zeekctl.cfg /usr/local/zeek/etc/

curl -L -O  https://raw.githubusercontent.com/LMehavilla/ConfFiles/main/python_broker.py

curl -L -O  https://raw.githubusercontent.com/LMehavilla/ConfFiles/main/model.joblib

#python3 preprocess.py
#zeekctl deploy
#LD_PRELOAD=/usr/lib/arm-linux-gnueabihf/libatomic.so.1.2.0 python python_broker.py &
