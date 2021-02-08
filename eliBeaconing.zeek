@load base/frameworks/sumstats
@load base/utils/time
@load base/frameworks/notice

module HTTP;
module signature;

#signature beaconing-sig {
 #   src-ip == 10.0.0.2
  #  dst-ip == 10.0.0.3
   # ip-proto == tcp
    #dst-port == 80
    #http-request /(*en-us/(docs.html?* | test.html?* | index.html?*))/
    #event "possible C2 Connection"
#}

#event signature_match(state: signature_state, msg: string, data: string)
#{
#    print("Possible C2 Detection")
#}

event connection_state_remove(c: connection)
{
    #Here we make the observation of the packet size in those given times (looking for the max)
    #Or whatever we are trying to look at
    SumStats::observe("packet sizes from connection",
                        SumStats::Key() #what piece of data do we want to look at specifically
                        SumStats::Observation())
}








