module covenant;

export {
    redef enum Log::ID += { covenant::LOG };

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

    # User definable high http trans depth
    global high_http_trans_depth = 10 &redef;

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        covenant_endpoint_found: string &log;
    };
}

event zeek_init(){
    Log::create_stream(covenant::LOG, [$columns=covenant::Info, $path="covenant"]);
}

# Check to see if the endpoint matches one of the known endpoints
# Check for the number of back and forth requests/responses.
event HTTP::log_http(rec: HTTP::Info){
    if(covenantEndpoints in rec$uri){
        if(rec$trans_depth > high_http_trans_depth){
            Log::write(covenant::LOG, covenant::Info($ts=rec$ts, $uid=rec$uid, $id=rec$id, $covenant_endpoint_found=rec$uri));
            NOTICE([$note=covenantTraffic, $ts=rec$ts, $uid=rec$uid, $id=rec$id, $msg = "Covenant Traffic Has Been Detected", $identifier=cat($id=rec$id), $suppress_for=5min]);
        }
    }
}



# --Email portion--
#@load ../main
#@load base/utils/site
#
#module Notice;
#
#export {
#	redef enum Action += {
#		ACTION_EMAIL_ADMIN
#	};
#}
#
#hook notice(n: Notice::Info) &priority=-5
#	{
#	if ( |Site::local_admins| > 0 &&
#	     ACTION_EMAIL_ADMIN in n$actions )
#		{
#		local email = "";
#		if ( n?$src && |Site::get_emails(n$src)| > 0 )
#			email = fmt("%s, %s", email, Site::get_emails(n$src));
#		if ( n?$dst && |Site::get_emails(n$dst)| > 0 )
#			email = fmt("%s, %s", email, Site::get_emails(n$dst));
#
#		if ( email != "" )
#			email_notice_to(n, email, T);
#		}
#	}
#
## Basic notice draft
#hook Notice::policy(n: Notice::Info) &priority=5
#    {
#    # Insert your code here.
#    if ( )
#         add n$actions[Notice::ACTION_EMAIL];
#
#    	#Extra information to be added to email body sections
#    	#This one for http requests as shown in the Zeek Manual
#    	if ( n?$conn && n$conn?$http && n$conn$http?$host )
#    	n$email_body_sections[|n$email_body_sections|] = fmt("HTTP host header: %s", n$conn$http$host);
#    }
#
#
## Raising notices
#NOTICE([$note=Password_Guessing,
#        $msg=fmt("%s appears to be guessing SSH passwords (seen in %d connections).", key$host, r$num),
#        $src=key$host,
#        $identifier=cat(key$host)]);
#
