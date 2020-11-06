@load base/frameworks/sumstats
@load base/utils/time
@load base/frameworks/notice

module portScan

export 
{

    redef enum Notice::Type += {
		Typeof_Scan
        
        ## Address scans detect that a host appears to be scanning some
		## number of destinations on a single port. This notice is
		## generated when more than :zeek:id:`Scan::addr_scan_threshold`
		## unique hosts are seen over the previous
		## :zeek:id:`Scan::addr_scan_interval` time range.
		Address_Scan,

		## Port scans detect that an attacking host appears to be
		## scanning a single victim host on several ports.  This notice
		## is generated when an attacking host attempts to connect to
		## :zeek:id:`Scan::port_scan_threshold`
		## unique ports on a single host over the previous
		## :zeek:id:`Scan::port_scan_interval` time range.
		Port_Scan,
	};
    
    # Const variable definitions here depending on scan types
    const typeof_scan_interval = 5min &redef;
    const typeof_scan_threshold = 25.0 &redef;
    global Scan::typeof_scan_policy: hook(scanner: addr, victim: addr, scanned_port: port);
}

event zeek_init()
{
    #Parts of sum stats that we will need to scan the ports
    
    # Create the reducer.
    # The reducer attaches to the "conn attempted" observation stream
    # and uses the summing calculation on the observations. Keep
    # in mind that there will be one result per key (connection originator).
    local r1 = SumStats::Reducer($stream="scan.typeof", 
                                 $apply=set(SumStats::SUM));
                                 
    SumStats::create([$name="typeof-scan",
	                  $epoch=typeof_scan_interval,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["scan.typeof.fail"]$unique+0.0;
	                  	},
	                  #$threshold_func=check_typeof_scan_threshold,
	                  $threshold=typeof_scan_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
				## print fmt("%s attempted %.0f or more connections", key$host, result["conn attempted"]$sum);
	                  	local r = result["scan.typeof.fail"];
	                  	local side = Site::is_local_addr(key$host) ? "local" : "remote";
	                  	local dur = duration_to_mins_secs(r$end-r$begin);
	                  	local message=fmt("%s scanned at least %d unique hosts on port %s in %s", key$host, r$unique, key$str, dur);
	                  	NOTICE([$note=Typeof_Scan,
	                  	        $src=key$host,
	                  	        $p=to_port(key$str),
	                  	        $sub=side,
	                  	        $msg=message,
	                  	        $identifier=cat(key$host)]);
	                  	}]);                             
    
                                 
    local r2 = SumStats::Reducer($stream="", 
                                 $apply=set(SumStats::UNIQUE));
                                 
    
}

function add_sumstats(id: conn_id, reverse: bool)
	{
	local source       = id$orig_h;
	local destin       = id$resp_h;
	local scanned_port = id$resp_p;

	if ( reverse )
		{
		source       = id$resp_h;
		destin       = id$orig_h;
		scanned_port = id$orig_p;
		}

	if ( hook Scan::addr_scan_policy(scanner, victim, scanned_port) )
		SumStats::observe("scan.addr.fail", [$host=scanner, $str=cat(scanned_port)], [$str=cat(victim)]);

	if ( hook Scan::port_scan_policy(scanner, victim, scanned_port) )
		SumStats::observe("scan.port.fail", [$host=scanner, $str=cat(victim)], [$str=cat(scanned_port)]);
	}

#Identify source and destination IP address


#Identify source and destination ports (80)


#Epoch (How many different IP addresses are in that time interval)

#Counter for how many IP addresses 

#Check on the criteria
    #Is the port port 80
    #right timeframe
    #the source IP has scanned, a threshold for how many times it has scanned
    
#Log the source IP address(if it fits the criteria)



