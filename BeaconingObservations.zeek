@load base/frameworks/sumstats
@load base/protocols/conn
@load base/protocols/http

# We use the connection_attempt event to limit our observations to those
# which were attempted and not successful.
event connection_state_remove(c: connection)
    {
    # Make an observation!
    # This observation is about reponse length from covenant
    SumStats::observe("response length from responding hosts",
                        SumStats::Key($host = c$id$resp_h), #can be changed to be a specific IP address or a range of addresses
                        SumStats::Observation($num = c$resp$size));
    #observation for num packets
    SumStats::observe("num packets from origin",
                        SumStats::Key($host = c$id$orig_h),
                        SumStats::Observation($num = c$orig$num_pkts));
    }

event zeek_init()
    {
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
                          print fmt("%s responded with combined body lengths of %.0f bytes in its connections in that time frame", key$host, result["response length from responding hosts"]$sum);
                      }
            		  ]);

        #create sum stats for num packets from origin
        SumStats::create([$name = "num packets from origin",
                      $epoch = 5min,
                      $reducers = set(numPacketsReducer),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        # This is the body of the callback that is called when a single 
                        # result has been collected.  We are just printing the total number
                        # of connections that were seen.  The $sum field is provided as a 
                        # double type value so we need to use %f as the format specifier.
                        print fmt("Number of packets sent from %s: %.0f",key$host, result["num packets from origin"]$sum);
                        }]);              
                   
    }
