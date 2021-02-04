@load base/protocols/conn

# Append a new notice value to the Notice::Type enumerable.
redef enum Notice::Type += { austinsType };


# find or mimic a threshold of the trans_depth var. only when its more than like 5 or 10 use the notice framework. example:  trans_depth > 5

event connection_state_remove(c: connection){
    asdfasdf
    NOTICE([$note=austinsType, $msg = "It worked. I have this random line written down!", $conn=c]);
}
