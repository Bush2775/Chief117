# Store the time the previous connection was established.
global last_connection_time: time;
# boolean value to indicate whether we have seen a previous connection.
global connection_seen: bool = F;
event connection_established(c: connection)
    {
    local net_time: time  = network_time();
    print fmt("%s:  New connection established from %s to %s", strftime("%Y/%m/%d %H:%M:%S", net_time), c$id$orig_h, c$id$resp_h);
    if ( connection_seen )
    {
        print fmt("     Time since last connection: %s", net_time - last_connection_time);
        #print fmt("     Time since last connection: %s", time_to_double(net_time) - time_to_double(last_connection_time));
        SumStats::observe("time delta",
                        SumStats::Key($host = c$id$resp_h), #can be changed to be a specific IP address or a range of addresses
                        SumStats::Observation($dbl = time_to_double(net_time) - time_to_double(last_connection_time)));
	}
    last_connection_time = net_time;
    connection_seen = T;
    }
event zeek_init()
    {
        local connectionDeltaReducer = SumStats::Reducer($stream="time delta",
                                                        $apply=set(SumStats::AVERAGE));
        #create sumstats for tracking time delta between connections
        SumStats::create([$name = "tracking time delta",
                      $epoch = 5min,
                      $reducers = set(connectionDeltaReducer),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                      {
                          print fmt("Average delta time between %s connections sent from %s: %s", result["time delta"]$num+1, key$host, double_to_time(result
                          ["time delta"]$average));
                      }
                      ]);
    }
