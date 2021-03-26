module delta;

# Store the time the previous connection was established.
global last_connection_time: time;
# boolean value to indicate whether we have seen a previous connection.
global connection_seen: bool = F;

export {
	redef enum Log::ID += { delta::LOG };
	
	type Info: record {
        ts: time &log;
        orig_h: string &log;
        resp_h: addr &log;
        avg: time &log;
        min: double &log;
        max: double &log;
        num: int &log;
	};
}

event connection_established(c: connection)
    {
    local net_time: time  = network_time();
    #print fmt("%s:  New connection established from %s to %s", strftime("%Y/%m/%d %H:%M:%S", net_time), c$id$orig_h, c$id$resp_h);
    if ( connection_seen )
    {
        #print fmt("     Time since last connection: %s", net_time - last_connection_time);
        SumStats::observe("time delta",
                        SumStats::Key($host = c$id$resp_h, $str = fmt("%s", c$id$orig_h)),
                        SumStats::Observation($dbl = time_to_double(net_time) - time_to_double(last_connection_time)));
	}
    last_connection_time = net_time;
    connection_seen = T;
    }
event zeek_init()
    {
		Log::create_stream(delta::LOG, [$columns=Info, $path="delta"]);
		
        local connectionDeltaReducer = SumStats::Reducer($stream="time delta",
                                                        $apply=set(SumStats::MIN, SumStats::MAX, SumStats::AVERAGE));
        #create sumstats for tracking time delta between connections
        SumStats::create([$name = "tracking time delta",
                      $epoch = 5min,
                      $reducers = set(connectionDeltaReducer),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                      {
                          #print fmt("Average delta time between %s connections sent from %s: %s", result["time delta"]$num+1, key$host, double_to_time(result["time delta"]$average));
                          #print fmt("Delay: %s Min: %s Max: %s", result["time delta"]$average, result["time delta"]$min, result["time delta"]$max);
		          Log::write(delta::LOG, Info($ts=ts, $orig_h=key$str, $resp_h=key$host, $avg=double_to_time(result["time delta"]$average),
						$min=result["time delta"]$min, $max=result["time delta"]$max, $num=result["time delta"]$num+1));
                      }
                      ]);
    }
