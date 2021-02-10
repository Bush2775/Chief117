@load base/protocols/http

event analyze_http_content(f: fa_file, data: string)
	{
	print "DATA:", data;
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( c?$http  )
		{
		#print "The event was triggered by the file over new conn";
		print "uri", c$http$uri;
		print "response_body_len", c$http$response_body_len;
		print "HTTP body", c$http;
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=analyze_http_content]);
		}
	}