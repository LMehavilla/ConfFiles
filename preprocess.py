zeek_file=open('ip_list_was.txt', 'w')
zeek_file.write('#fields\tip\n')
with open('whatsapp_cidr_ipv4.txt', 'r') as f:
    for linea in f:
      #print(linea)
      #if('#' in linea):
        #print(linea)
      if not('#' in linea):
        ip_mask=linea.split('/')
        #zeek_file.write(ip_mask[0]+' '+ip_mask[1])
        #lo que debe hacer zeek para meterlos en un vector todos
        #print(ip_mask[0])
        #print(ip_mask[1])
        if(ip_mask[1]=='31\n'):
          #print('entra')
          part=ip_mask[0].split('.')
          #print(int(part[3])+1)
          #print(str(part[0])+'.'+str(part[1])+'.'+str(part[2])+'.'+str(int(part[3])+1))
          zeek_file.write(str(part[0])+'.'+str(part[1])+'.'+str(part[2])+'.'+str(int(part[3])+1)+'\n')
        zeek_file.write(ip_mask[0]+'\n')

zeek_file.close()
