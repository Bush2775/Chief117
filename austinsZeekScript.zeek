# Append a new notice value to the Notice::Type enumerable.
redef enum Notice::Type += { austinsType };

event connection_state_remove(c: connection){
    NOTICE([$note=austinsType, $msg = "It worked. I have this random line written down!", $conn=c]);
}

## endpoints to attempt matching against.
global matchEndpoints = /\/en-us\/index.html\?page=[a-zA-Z0-9]+\&v=1/ |
                        /\/en-us\/docs.html\?type=[a-zA-Z0-9]+\&v=1/ |
                        /\/en-us\/test.html\?message=[a-zA-Z0-9]+\&v=1/;

event HTTP::log_http(rec: HTTP::Info){
    print rec$trans_depth;
    if(matchEndpoints in rec$uri){
        print "I found it!", rec$uri;
    }
}

#event http_stats(c: connection, stats: http_stats_rec){
#    print stats;
#}


#HttpUrls:
#    - /en-us/index.html?page={GUID}&v=1
#    - /en-us/docs.html?type={GUID}&v=1
#    - /en-us/test.html?message={GUID}&v=1
#HttpRequestHeaders:
#    - Name: User-Agent
#      Value: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36
#HttpPostRequest: |
#    i=a19ea23062db990386a3a478cb89d52e&data={DATA}&session=75db-99b1-25fe4e9afbe58696-320bea73
#HttpPostResponse: |
#    <html>
#        <head>
#            <title>Hello World!</title>
#        </head>
#        <body>
#            <p>Hello World!</p>
#            // Hello World! {DATA}
#        </body>
#    </html>
