module lookWhatIFound;

export {
    redef enum Log::ID += { lookWhatIFound::LOG };

    const allowed: table[subnet] of set[subnet] = {
        [10.0.0.0/24] = set(11.0.0.0/24, 12.0.0.0/24)
    } &redef;

    type Info: record {
        ts: time &log;
        src: addr &log;
        dest: addr &log;
    };
}

event zeek_init(){
    Log::create_stream(LOG, [$columns=Info, $path="lookWhatIFound"]);
}

event connection_established(c: connection){
    if (c$id$orig_h in allowed){
        if (c$id$resp_h !in allowed[c$id$orig_h]){
            Log::write(LOG, Info($ts=network_time(), $src=c$id$orig_h, $dest=c$id$resp_h));
        }
    }
}
