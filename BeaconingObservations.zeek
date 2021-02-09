@load base/frameworks/sumstats
@load base/protocols/conn
@load base/protocols/http

# We use the connection_attempt event to limit our observations to those
# which were attempted and not successful.
event connection_state_remove(c: connection)
    {
    # Make an observation!
    # This observation is about num_pkts sent from victim
    SumStats::observe("num packets from origin",
                        SumStats::Key($host=c$id$orig_h), #can be changed to be a specific IP address or a range of addresses
                        SumStats::Observation($num=c$orig$num_pkts));

    }

event zeek_init()
    {
        local beaconReducer = SumStats::Reducer($stream="num packets from origin",
                                                $apply=set(SumStats::MAX));

        SumStats::create([$name = "tracking max packets",
                      $epoch = 5min,
                      $reducers = set(beaconReducer)
            		  ]);
                      
                   
    }
