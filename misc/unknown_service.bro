module UnknownService;

# A simple approach to detecting unknown protocols on known ports. To expand
# the ports that are monitored just add them to the monitored_ports variable.
#
# Notices will be generated for connections that meet the other requirements
# but aren't a monitored port.
#
# Mike (sooshie@gmail.com)

export {
    redef enum Notice::Type += { Unknown::Service };
    const monitored_ports: set[port] = { 80/tcp, 443/tcp, 53/tcp } &redef;
}

event Conn::log_conn(rec: Conn::Info)
    {
    if (!rec?$service && rec$missed_bytes == 0 && rec?$resp_bytes && rec?$orig_bytes )
        {
        local total_bytes = rec$resp_bytes + rec$orig_bytes;
        if ( total_bytes > 150 && interval_to_double(rec$duration) > 5.0 )
            {
            local ip = rec$id$resp_h;
            local c: connection;
            local cid: conn_id;
            c$id = cid;
            c$uid = rec$uid;
            c$id$orig_h = rec$id$orig_h;
            c$id$resp_h = rec$id$resp_h;
            c$id$resp_p = rec$id$resp_p;
            c$id$orig_p = rec$id$orig_p;
            if ( rec$id$resp_p in monitored_ports )
                {
                NOTICE([$note=Unknown::Service, $msg=fmt("Unknown service over a monitored port (%s)", rec$id$resp_p), 
                        $conn=c, $suppress_for=30mins, $identifier=cat(c$id$orig_h,c$id$resp_h,c$id$resp_p)]);
                return;
                }
            if ( rec$proto == tcp )
                NOTICE([$note=Unknown::Service, $msg=fmt("Unknown service over port (%s)", rec$id$resp_p), 
                        $conn=c, $suppress_for=30mins, $identifier=cat(c$id$orig_h,c$id$resp_h,c$id$resp_p)]);
            }
        }
    }
