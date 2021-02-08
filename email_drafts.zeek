# Password guessing notice
@load protocols/ssh/detect-bruteforcing

redef SSH::password_guesses_limit=10;

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == SSH::Password_Guessing && /192\.168\.56\.103/ in n$sub )
        add n$actions[Notice::ACTION_EMAIL];
    }

# Basic notice draft
hook Notice::policy(n: Notice::Info) &priority=5
    {
    # Insert your code here.
    if ( )
         add n$actions[Notice::ACTION_EMAIL];
    }


# Raising notices
NOTICE([$note=Password_Guessing,
        $msg=fmt("%s appears to be guessing SSH passwords (seen in %d connections).", key$host, r$num),
        $src=key$host,
        $identifier=cat(key$host)]);


#Extra information to be added to email body sections
#This one for http requests as shown in the Zeek Manual
hook Notice::policy(n: Notice::Info)
  {
  if ( n?$conn && n$conn?$http && n$conn$http?$host )
    n$email_body_sections[|n$email_body_sections|] = fmt("HTTP host header: %s", n$conn$http$host);
  }



# ---FROM ZEEK GIT 'zeek/email_admin.zeek'---
##! Adds a new notice action type which can be used to email notices
##! to the administrators of a particular address space as set by
##! :zeek:id:`Site::local_admins` if the notice contains a source
##! or destination address that lies within their space.

@load ../main
@load base/utils/site

module Notice;

export {
	redef enum Action += {
		## Indicate that the generated email should be addressed to the 
		## appropriate email addresses as found by the
		## :zeek:id:`Site::get_emails` function based on the relevant 
		## address or addresses indicated in the notice.
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
