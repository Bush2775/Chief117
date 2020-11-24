##! Add an excerpt of HTTP POST bodies into the HTTP log.

@load base/protocols/http

event analyze_http_content(f: fa_file, data: string)
	{
#		print data;
		local postedData:PatternMatchResult = match_pattern(data, /data=.*&/);
		local encodedData:string = postedData$str;
		encodedData = sub(encodedData,/data=/,"");
		encodedData = sub(encodedData,/&/,"");
#		print encodedData;
		local decodedData:string = decode_base64(encodedData);
		print decodedData;
		print "************************";
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( c?$http && c$http?$method && ( c$http$method == "POST" ) )
		{
		#print "The event was triggered by the file over new conn";
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=analyze_http_content]);
		}
	}
