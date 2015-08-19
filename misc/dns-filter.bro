module FILTER;

export {
    global filter_dnslog_hostnames: set[string] &redef;
    const filter_bonjour_requests = F &redef;
}

function filter_dnslog(rec: DNS::Info) : bool
    {
    if ( !rec?$query )
        return T;
    if ( filter_bonjour_requests && /^(b|db|r|dr|lb)\._dns-sd\._udp/ in rec$query )
        return F;
    if ( rec$query in filter_dnslog_hostnames )
        return F;
    return T;
    }

# Used to filter HTTP logs by removing the existing one and putting a filtered one in its place
event bro_init()
        {
        # First remove the default filter.
        Log::remove_default_filter(DNS::LOG);
        # Add the filter to direct logs to the appropriate file name.
        Log::add_filter(DNS::LOG, [$name = "dns",
                                   $path = "dns",
                                   $pred = filter_dnslog
                                   ]);
        }
