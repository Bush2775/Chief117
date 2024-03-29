@load base/frameworks/sumstats
@load base/protocols/conn
@load base/protocols/http

export {
    # Log ID for Num Packets Sum Stat
    redef enum Log::ID += { Packets::LOG };

    # Append a new notice value to the Notice::Type enumerable.
    redef enum Notice::Type += { covenantTraffic };

    # Notice policy to tell it to log the notice.
    hook Notice::policy(n: Notice::Info){
        add n$actions[Notice::ACTION_LOG];
    }

    # Covenant endpoints to attempt matching against.
    global covenantEndpoints = /\/en-us\/index.html\?page=[a-zA-Z0-9]+\&v=1/ |
                                /\/en-us\/docs.html\?type=[a-zA-Z0-9]+\&v=1/ |
                                /\/en-us\/test.html\?message=[a-zA-Z0-9]+\&v=1/ &redef;

    #define record variable for Packets Log
    type Info: record {
        ts: time &log;
        orig_h: addr &log;
        num_pkts: double &log;
	};

    #Log ID for response Length
    redef enum Log::ID += { ResponseLength::LOG };

    # define record variable for response length log
    type Info2: record {
        ts: time &log;
        resp_h: addr &log;
        resp_length: double &log;
	};
}

# Using the connection_state_remove event We can get the necessary information to look at the connection
#and find evidence of beaconing.
#Other avenues of detection can be added by creating a new SumStat observe, reducer, and create function in the zeek_init()
event connection_state_remove(c: connection)
    {
    #create observation for response length
    SumStats::observe("response length from responding hosts",
                        SumStats::Key($host = c$id$resp_h), #This variable can be changed to look at a specific IP address or a range of IP addresses
                        SumStats::Observation($num = c$resp$size));
    #observation for num packets from origin
    SumStats::observe("num packets from origin",
                        SumStats::Key($host = c$id$orig_h),
                        SumStats::Observation($num = c$orig$num_pkts));

    }

event zeek_init()
    {
        #Creating log streams for the SumStats
        Log::create_stream(Packets::LOG, [$columns=Info, $path="numPackets"]);
        Log::create_stream(ResponseLength::LOG, [$columns=Info2, $path="responseLength"]);

        #reducers for the sumstats
        local responseLenReducer = SumStats::Reducer($stream="response length from responding hosts",
                                                        $apply=set(SumStats::SUM));

        local numPacketsReducer = SumStats::Reducer($stream = "num packets from origin",
                                                        $apply=set(SumStats::SUM));


        #create sumstats for tracking response length
        SumStats::create([$name = "tracking response length",
                      $epoch = 5min,
                      $reducers = set(responseLenReducer),
                      $threshold = 10000.0,
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                      {
                          return result["response length from responding hosts"]$sum;
                      },
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                      {
                          #The print statement below can be used for debugging
                          #print fmt("%s responded with combined body lengths of %.0f bytes in its connections in that time frame", key$host, result["response length from responding hosts"]$sum);

                          #statement to write to the log
                          Log::write(ResponseLength::LOG, Info2($ts=network_time(), $resp_h=key$host, $resp_length=result["response length from responding hosts"]$sum));
                      }
            		  ]);

        #create sum stats for num packets from origin
        SumStats::create([$name = "num packets from origin",
                      $epoch = 5min,
                      $reducers = set(numPacketsReducer),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {

                        #The print statement below can be used for debugging
                        #print fmt("Number of packets sent from %s: %.0f",key$host, result["num packets from origin"]$sum);

                        #statement to write to the log
                        Log::write(Packets::LOG, Info($ts=ts, $orig_h=key$host, $num_pkts=result["num packets from origin"]$sum));

                        }

                        ]);


    }

# Check to see if the endpoint matches one of the known endpoints
event HTTP::log_http(rec: HTTP::Info){
    if(covenantEndpoints in rec$uri){
        NOTICE([$note=covenantTraffic, $ts=rec$ts, $uid=rec$uid, $id=rec$id, $msg = "Default HTTP Covenant Endpoint Has Been Detected", $identifier=cat($id=rec$id), $suppress_for=5min]);
    }
}
