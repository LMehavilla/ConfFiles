import sys
import broker
import joblib
import json

print("start")
# Setup endpoint and connect to Zeek.
ep=broker.Endpoint()
sub=ep.make_subscriber("test/topic1")
ss=ep.make_status_subscriber(True)

#quien inicia la conexión
print("peer")
ep.listen("127.0.0.1", 1234)

print("wait connection")
    # Wait until connection is established.
st = ss.get()

if not (type(st) == broker.Status):
   print("could not connect")
   print(st)
   print(type(st), broker.Status)
   print(st.code()==broker.SC.PeerAdded)
   sys.exit(0)

print(type(st))
print(st.code())
print("connected")

#cargar modelo de clasifiacioón
model=joblib.load("/root/model.joblib")
labels=model.classes_

#for n in range (5):
while True:
        print("waiting to receive")
        (t, d) = sub.get()
        pong =broker.zeek.Event(d)
        #print("received{}{}".format(pong.name(), pong.args()))
        
        data=pong.args()[0]
        
        if(data[1] is  None):
            break            
        
        destinationAddress=str(data[0])
        sourceAddress=str(data[1])
        time=data[30]
        sourceDnsDomain=', '.join(data[20])
        destinationDnsDomain=', '.join(data[21])
        sourceHostName=', '.join(data[22])
        destinationHostName=', '.join(data[23])
        
        mediaOrigen=float(str(data[24]))
        mediaResp=float(str(data[25]))
        desvOrigen=float(str(data[26]))
        desvResp=float(str(data[27]))
        noceroOrigen=float(str(data[28]))
        noceroResp=float(str(data[29]))
        duration3=data[32].total_seconds()
        mediaTime=float(str(data[33]))
        desvTime=float(str(data[34]))
        
        #print("device "+sourceAddress+" at "+time)
        #print("mediaOrigen "+str(data[24])+" mediaResp "+str(data[25])+" desvOrigen "+str(data[26])+" desvResp "+str(data[27]) +" noceroOrigen "+str(data[28])+" noceroResp "+ str(data[29])+" duration3 "+str(data[32])+" mediaTime "+ str(data[33])+" desvTime "+str(data[34]))
        
        x=[mediaOrigen,mediaResp,desvOrigen,desvResp,noceroOrigen,
            noceroResp,duration3,mediaTime,desvTime]
            
        y_pred= model.predict_proba([x])
        
        for y in y_pred:
            ind_sorted=np.argsort(y)[::-1]
            e=labels[ind_sorted[0]]
            print(e)
            
            max_labels_with_prob=(str(labels[ind_sorted[0]])+": "+str(y[ind_sorted[0]])+", "+ 
             str(labels[ind_sorted[1]])+": "+ str(y[ind_sorted[1]])+", "+ 
             str(labels[ind_sorted[2]])+": "+ str(y[ind_sorted[2]])+", "+
             str(labels[ind_sorted[3]])+": "+ str(y[ind_sorted[3]]))
             
        
        #print("message "+y_pred+" device "+sourceAddress+" at "+time)
        #print(y_pred[0])
        
        file=open('timeline.log', 'a')
        """
        e=y_pred[0]
        if(y_pred[0]=='Descarga'):
            e='D'
        elif(y_pred[0]=='Permanencia'):
            e='SB'
        elif(y_pred[0]=='KeepAlive'):
            e='KA'
        elif(y_pred[0]=='Señalizacion Envio Archivo'):
            e='FST'
        elif(y_pred[0]=='Señalizacion Envio Audio'):
            e='AST'
        elif(y_pred[0]=='Señalizacion Envio Foto'):
            e='PST'
        elif(y_pred[0]=='Señalizacion Envio Sticker'):
            e='SST'
        elif(y_pred[0]=='Señalizacion Envio Texto'):
            e='TST'
        elif(y_pred[0]=='Señalizacion Envio Video'):
            e='VST'
        elif(y_pred[0]=='Señalizacion Recepcion Archivo'):
            e='FSR'
        elif(y_pred[0]=='Señalizacion Recepcion Audio'):
            e='ASR'
        elif(y_pred[0]=='Señalizacion Recepcion Foto'):
            e='PSR'
        elif(y_pred[0]=='Señalizacion Recepcion Sticker'):
            e='SSR'
        elif(y_pred[0]=='Señalizacion Recepcion Texto'):
            e='TSR'
        elif(y_pred[0]=='Señalizacion Recepcion Video'):
            e='VSR'
        elif(y_pred[0]=='Señalizacion Llamadas'):
            e='SC'
        elif(y_pred[0]=='Subida'):
            e='U'
        """
        result={"event": e, "timestamp": time, "sourceAddress": sourceAddress, "destinationAddress": destinationAddress,
           "sourceDnsDomain": sourceDnsDomain, "destinationDnsDomain": destinationDnsDomain,
            "sourceHostName": sourceHostName, "destinationHostName": destinationHostName,
            "max_labels_with_prob": max_labels_with_prob}
        json.dump(result, file)
        file.write('\n')
        file.close()
