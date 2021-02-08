@load ../main
@load base/utils/site

module Notice;

export {
	redef enum Action += {
		ACTION_EMAIL_ADMIN
	};
}

hook notice(n: Notice::Info) &priority=-5
	{
	if ( |Site::local_admins| > 0 &&
	     ACTION_EMAIL_ADMIN in n$actions )
		{
		local email = "";
		if ( n?$src && |Site::get_emails(n$src)| > 0 )
			email = fmt("%s, %s", email, Site::get_emails(n$src));
		if ( n?$dst && |Site::get_emails(n$dst)| > 0 )
			email = fmt("%s, %s", email, Site::get_emails(n$dst));
		
		if ( email != "" )
			email_notice_to(n, email, T);
		}
	}




# Basic notice draft
hook Notice::policy(n: Notice::Info) &priority=5
    {
    # Insert your code here.
    if ( )
         add n$actions[Notice::ACTION_EMAIL];
    
    	#Extra information to be added to email body sections
    	#This one for http requests as shown in the Zeek Manual
    	if ( n?$conn && n$conn?$http && n$conn$http?$host )
    	n$email_body_sections[|n$email_body_sections|] = fmt("HTTP host header: %s", n$conn$http$host);
    }


# Raising notices
NOTICE([$note=Password_Guessing,
        $msg=fmt("%s appears to be guessing SSH passwords (seen in %d connections).", key$host, r$num),
        $src=key$host,
        $identifier=cat(key$host)]);

