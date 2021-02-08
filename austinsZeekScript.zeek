module covenant;

export {
    redef enum Log::ID += { covenant::LOG };

    # Covenant endpoints to attempt matching against.
    global covenantEndpoints = /\/en-us\/index.html\?page=[a-zA-Z0-9]+\&v=1/ |
                                /\/en-us\/docs.html\?type=[a-zA-Z0-9]+\&v=1/ |
                                /\/en-us\/test.html\?message=[a-zA-Z0-9]+\&v=1/ &redef;

    # User definable high http trans depth
    global high_http_trans_depth = 10 &redef;

    type Info: record {
        ts: time &log;
        id: conn_id &log;
        high_http_trans_depth_found: bool &log;
        covenant_endpoint_found: bool &log;
    };
}

event zeek_init(){
    Log::create_stream(covenant::LOG, [$columns=covenant::Info, $path="covenant"]);
}

# Check for the number of back and forth requests/responses.
# Also check to see if the endpoint matches one of the known endpoints
event HTTP::log_http(rec: HTTP::Info){
    if(rec$trans_depth > high_http_trans_depth){
        print rec$trans_depth;
    }
    if(covenantEndpoints in rec$uri){
        print rec$uri;
    }
}

event connection_state_remove(c: connection){
    if(T){
        Log::write(covenant::LOG, covenant::Info($ts=network_time(), $id=c$id, $high_http_trans_depth_found=T, $covenant_endpoint_found=T));
        #NOTICE([$note=covenantTraffic, $msg = "Covenant Traffic Has Been Detected", $conn=c, $identifier=cat(c$id), $suppress_for=5min]);
    }
}

# Append a new notice value to the Notice::Type enumerable.
#redef enum Notice::Type += { covenantTraffic };

# Notice policy which can change where the notice is sent.
#hook Notice::policy(n: Notice::Info){
#	add n$actions[Notice::ACTION_LOG];
#    #add n$actions[Notice::ACTION_EMAIL];
#}
