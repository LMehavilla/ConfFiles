@load base/protocols/conn
@load base/utils/time
@load base/protocols/ssl
@load base/protocols/dns
@load base/files/x509

module Conn;

export {
		function set_conn_log_data_hack(c: connection)
			{
				Conn::set_conn(c, T);
			}
}

module Was_Machine;


export {
	redef enum Log::ID += { LOG };
	
	type Data: record{
		destinationAddress: addr &log;
		sourceAddress: addr &log;
		destinationPort: port &log;
		sourcePort: port &log;
		startTime: string &log;
		protocol: string &log;
		service:	string &log ;
		duration:	interval &log;
		orig_bytes:	count &log;
		resp_bytes: count &log;
		conn_state:	string &log;
		local_orig:	bool &log;
		local_resp: bool &log;
		missed_bytes: count &log;
		history:	string &log;
		orig_pkts:	count &log;
		orig_ip_bytes:	count &log;
		resp_pkts:	 count &log;
		resp_ip_bytes:	count &log;
		tunnel_parents:	set[string] &log;
		
		sourceDnsDomain:	vector of string &log ;
		destinationDnsDomain:	vector of string &log ;
		
		sourceHostName:	vector of string &log ;
		destinationHostName:	vector of string &log ;	
		
		mediaOrigen: double &log;
		mediaResp: double &log;
		desvOrigen: double &log;
		desvResp: double &log;
		noceroOrigen: count &log;
		noceroResp: count &log;
		
		startTime2: string &log;
		duration2: interval &log;
		duration3: interval &log;
		mediaTime: double &log;
		desvTime: double &log;
	};
	
	type almacen: record{
		duration: interval;
		orig_bytes: vector of count;
		resp_bytes: vector of count;
		last_orig: count;
		last_resp: count;
		nocero_orig: count;
		nocero_resp: count;
		initime: time;
		last_dur: interval;
		dur_interval: vector of interval;
	};
		
	global dns: table [addr] of vector of string= table() &create_expire=1 day;
		
	global ssl: table [addr] of vector of string= table() &create_expire=1 day;
	
	global wardrobe: table [conn_id] of almacen= table();
	
	global send: event(d: Data);
	
	type Idx: record{
		ip: addr;
	};
	
	#set donde se van a encontrar todas las direcciones IP asociadas a whatsapp
	global ip_was: set[addr] = set();

}
redef record connection += {
        ## Offset of the currently watched connection duration by the long-connections script.
        long_conn_offset: count &default=0;
};

event zeek_init() {
        Log::create_stream(LOG, [$columns=Data, $path="was_machine"]);
		
		Input::add_table([$source=fmt("%s/ip_list_was.txt", "/home/pi/scripts") , $name="iplist", $idx=Idx, $destination=ip_was, $mode=Input::REREAD]);
			#name -> corresponde al input stream para leer los datos en una tabla (una vez leidos lo borramos)
				#pero si queremos que la lista se actualice cuando cambie el contenido del fichero, este stream debe continuar abierto
			#$mode=Input::REREAD -> permite que Zeek este observando todo el rato el archivo en busca de un cambio
				#cuando esto ocurre, se actualiza el set y se vuelve a lanzar en evento input::end_of_data	
			
		#para lanzarlo con zeekctl en modo cluster es necesario indicar que nodo (manager, proxy o worker) se va a unir al topic
		#porque si no se indica todos se intentaran unir e intentaran ponerse a escuchar en el puerto indicado (lo que hara que pete)
        	
		Broker::subscribe("test/topic1");
		Broker::peer("127.0.0.1", 1234/tcp, 1secs);
		Broker::auto_publish("test/topic1", send);
		
}

event dns_A_reply (c: connection, msg: dns_msg, ans: dns_answer, a: addr){
    
	local it_is=0;
	
	if (a !in dns){#si en la tabla dns no hay un linea con índice a
		dns[a]=[ans$query];
	}
	else{#si en la tabla dns hay una línea con indice a
		for (name in dns[a]){ #recorro la linea comprobando si alguno de los valores contenidos corresponde con el nombre seleccionado
			if (dns[a][name]==ans$query){
				it_is=1;#la linea tiene el nombre resuelto almacenado
			}
		}
		if(it_is!=1){#la linea no tiene el nombre resuelto almacenado
			dns[a]+=ans$query;
		}
	}

}

event ssl_established (c: connection){
	if (c$ssl?$server_name){
	
		local it_is=0;
	
		if (c$ssl$id$resp_h !in ssl){
			ssl[c$ssl$id$resp_h]=[c$ssl$server_name];
		}
		else{
			for (name in ssl[c$ssl$id$resp_h]){ 
				if (ssl[c$ssl$id$resp_h][name]==c$ssl$server_name){
					it_is=1;
				}
			}
			if(it_is!=1){
				ssl[c$ssl$id$resp_h]+=c$ssl$server_name;
			}
		}
	
		#ssl[c$ssl$id$resp_h]=c$ssl$server_name;
	}
	else{
		if (c$ssl$id$resp_h !in ssl){
			ssl[c$ssl$id$resp_h]=["SSL server not known name"];
		}
	}
	
}

function new_entry(c: connection){
	
	local datos: Was_Machine::almacen ;
	
	if(c$conn?$duration){
		datos$duration=c$conn$duration;
		datos$initime=(c$conn$ts+c$conn$duration);
		datos$dur_interval=[c$conn$duration];
		datos$last_dur=c$conn$duration;
	}
	else{
		datos$duration=0secs;
		datos$initime=c$conn$ts;
		datos$dur_interval=[0secs];
		datos$last_dur=0secs;
	}
	
	if(c$conn?$orig_bytes){
		datos$orig_bytes=[c$conn$orig_bytes];
		datos$last_orig=c$conn$orig_bytes;
		datos$nocero_orig=1;
	}
	else{
		datos$orig_bytes=[0];
		datos$last_orig=0;
		datos$nocero_orig=0;
	}
	
	if(c$conn?$resp_bytes){
		datos$resp_bytes=[c$conn$resp_bytes];
		datos$last_resp=c$conn$resp_bytes;
		datos$nocero_resp=1;
	}
	else{
		datos$resp_bytes=[0];	
		datos$last_resp=0;
		datos$nocero_resp=0;
	}
	
	wardrobe[c$conn$id]=datos;

}

function keep_new_data(c: connection){
	
	
	if(c$conn?$duration){
		wardrobe[c$conn$id]$duration=c$conn$duration;
		wardrobe[c$conn$id]$dur_interval+=(c$conn$duration-wardrobe[c$conn$id]$last_dur);
		wardrobe[c$conn$id]$last_dur=c$conn$duration;
	}
	
	if(c$conn?$orig_bytes){
		wardrobe[c$conn$id]$orig_bytes+=(c$conn$orig_bytes-wardrobe[c$conn$id]$last_orig);
	
		if ( (c$conn$orig_bytes-wardrobe[c$conn$id]$last_orig) > 0 ){
			wardrobe[c$id]$nocero_orig=wardrobe[c$conn$id]$nocero_orig+1;
		}
		wardrobe[c$conn$id]$last_orig=c$conn$orig_bytes;
	}
	
	if(c$conn?$resp_bytes){
		wardrobe[c$conn$id]$resp_bytes+=(c$conn$resp_bytes-wardrobe[c$conn$id]$last_resp);
	
		if ( (c$conn$resp_bytes-wardrobe[c$conn$id]$last_resp) > 0 ){
			wardrobe[c$id]$nocero_resp=wardrobe[c$conn$id]$nocero_resp+1;
		}		
		wardrobe[c$conn$id]$last_resp=c$conn$resp_bytes;
	}
	#print(wardrobe[c$conn$id]);

}

function keep_new_data2(c: connection){
	
	wardrobe[c$conn$id]$duration=c$conn$duration;
	wardrobe[c$conn$id]$initime=(c$conn$ts+c$conn$duration);
	wardrobe[c$conn$id]$dur_interval=[(c$conn$duration-wardrobe[c$conn$id]$last_dur)];
	wardrobe[c$conn$id]$last_dur=c$conn$duration;
	
	wardrobe[c$conn$id]$orig_bytes=[(c$conn$orig_bytes-wardrobe[c$conn$id]$last_orig)];

	if ( (c$conn$orig_bytes-wardrobe[c$conn$id]$last_orig) > 0 ){
		wardrobe[c$id]$nocero_orig=1;
	}
	else{
		wardrobe[c$id]$nocero_orig=0;
	}
	wardrobe[c$conn$id]$last_orig=c$conn$orig_bytes;


	wardrobe[c$conn$id]$resp_bytes=[(c$conn$resp_bytes-wardrobe[c$conn$id]$last_resp)];

	if ( (c$conn$resp_bytes-wardrobe[c$conn$id]$last_resp) > 0 ){
		wardrobe[c$id]$nocero_resp=1;
	}		
	else{
		wardrobe[c$id]$nocero_resp=0;
	}
	wardrobe[c$conn$id]$last_resp=c$conn$resp_bytes;
	
	#print(wardrobe[c$conn$id]);

}


function write_new_data(c: connection){

		local rec: Was_Machine::Data ;
			
		rec$startTime=strftime("%Y-%m-%d %H:%M:%S",c$conn$ts);
		
		rec$destinationAddress=c$id$resp_h;
		rec$sourceAddress=c$id$orig_h;
		rec$destinationPort=c$id$resp_p;
		rec$sourcePort=c$id$orig_p;
		rec$protocol=cat(c$conn$proto);
		
		if (c$conn?$service){
			rec$service=c$conn$service;
		}
		if (c$conn?$duration){
			rec$duration=c$conn$duration;
		}
		if(c$conn?$orig_bytes){
			rec$orig_bytes=c$conn$orig_bytes;
		}
		if(c$conn?$resp_bytes){
			rec$resp_bytes=c$conn$resp_bytes;
		}
		if (c$conn?$conn_state){
			rec$conn_state=c$conn$conn_state;
		}
		if (c$conn?$local_orig){
			rec$local_orig=c$conn$local_orig;
		}
		if (c$conn?$local_resp){
			rec$local_resp=c$conn$local_resp;
		}
		if (c$conn?$missed_bytes){
			rec$missed_bytes=c$conn$missed_bytes;
		}
		if (c$conn?$history){
			rec$history=c$conn$history;
		}
		if(c$conn?$orig_pkts){
			rec$orig_pkts=c$conn$orig_pkts;
		}
		if (c$conn?$orig_ip_bytes){
			rec$orig_ip_bytes=c$conn$orig_ip_bytes;
		}
		if(c$conn?$resp_pkts){
			rec$resp_pkts=c$conn$resp_pkts;
		}
		if (c$conn?$resp_ip_bytes){
			rec$resp_ip_bytes=c$conn$resp_ip_bytes;
		}
		if (c$conn?$tunnel_parents){
			rec$tunnel_parents=c$conn$tunnel_parents;
		}
		if (c$conn$id$orig_h in dns){
			rec$sourceDnsDomain=dns[c$conn$id$orig_h];
		}
		if (c$conn$id$resp_h in dns){
			rec$destinationDnsDomain=dns[c$conn$id$resp_h];
		}		
		
		if (c$conn$id$orig_h in ssl){
			rec$sourceHostName=ssl[c$conn$id$orig_h];
		}
		if (c$conn$id$resp_h in ssl){
			rec$destinationHostName=ssl[c$conn$id$resp_h];
		}

		local sum_ori =0.0;
		for ( i in wardrobe[c$conn$id]$orig_bytes){
			sum_ori+=wardrobe[c$conn$id]$orig_bytes[i];
		}
		local media_origen=(sum_ori/|wardrobe[c$conn$id]$orig_bytes|);
		rec$mediaOrigen=media_origen;

		local sum_resp =0.0;
		for (i in wardrobe[c$conn$id]$resp_bytes){
			sum_resp+=wardrobe[c$conn$id]$resp_bytes[i];
		}
		local media_resp=(sum_resp/|wardrobe[c$conn$id]$resp_bytes|);
		rec$mediaResp=media_resp;
		
		local sum_des_ori =0.0;
		for (i in wardrobe[c$conn$id]$orig_bytes){
			sum_des_ori+=((wardrobe[c$conn$id]$orig_bytes[i]-media_origen)*(wardrobe[c$conn$id]$orig_bytes[i]-media_origen));
		}
		rec$desvOrigen=sqrt(sum_des_ori/|wardrobe[c$conn$id]$orig_bytes|);
		
		local sum_des_resp =0.0;
		for (i in wardrobe[c$conn$id]$resp_bytes){
			sum_des_resp+= ((wardrobe[c$conn$id]$resp_bytes[i]-media_resp)*(wardrobe[c$conn$id]$resp_bytes[i]-media_resp));
		}
		rec$desvResp=sqrt(sum_des_resp/|wardrobe[c$conn$id]$resp_bytes|);
		
		rec$noceroOrigen=wardrobe[c$conn$id]$nocero_orig;
		rec$noceroResp=wardrobe[c$conn$id]$nocero_resp;
		
		rec$startTime2=strftime("%Y-%m-%d %H:%M:%S",wardrobe[c$conn$id]$initime);
		rec$duration2=(c$conn$duration-(wardrobe[c$conn$id]$initime-c$conn$ts));
		rec$duration3=(wardrobe[c$conn$id]$last_dur-(wardrobe[c$conn$id]$initime-c$conn$ts));
		
		local sum_int =0.0;
		for ( i in wardrobe[c$conn$id]$dur_interval){
			sum_int+=interval_to_double(wardrobe[c$conn$id]$dur_interval[i]);
		}
		local media_int=(sum_int/|wardrobe[c$conn$id]$dur_interval|);
		rec$mediaTime=media_int;
		
		local sum_des_int =0.0;
		for (i in wardrobe[c$conn$id]$dur_interval){
			sum_des_int+= ((interval_to_double(wardrobe[c$conn$id]$dur_interval[i])-media_int)*(interval_to_double(wardrobe[c$conn$id]$dur_interval[i])-media_int));
		}
		rec$desvTime=sqrt(sum_des_int/|wardrobe[c$conn$id]$dur_interval|);
		
		#print("escribe");
		#print(wardrobe[c$conn$id]);
		Log::write(Was_Machine::LOG, rec);
		
		#cada vez que se vaya escribir los tramos en el log también envío la info a python para que la analice con machine learning
		event send(rec);
}

event new_packet(c: connection, p: pkt_hdr){

		Conn::set_conn_log_data_hack(c);
		
		if (c$id$resp_h in ip_was)	{
			if(c$id in wardrobe){
				if(c$conn?$duration){
					if ( (c$conn$duration-wardrobe[c$conn$id]$duration) < 1sec ){
						keep_new_data(c);
					}
					else{
						write_new_data(c);
						keep_new_data2(c);
					}
				}
				else{
					keep_new_data(c);
				}
			}
			else{
				new_entry(c);
			}
		}
}

event connection_state_remove(c: connection){
				
	if (c$id$resp_h in ip_was)	{
		#print "end log conexion", c$id, c$duration;
		Conn::set_conn_log_data_hack(c);
		keep_new_data(c);
        write_new_data(c);
		delete wardrobe[c$conn$id];
	}
}

event zeek_done(){
	local rec: Was_Machine::Data ;
	event send(rec);
}
