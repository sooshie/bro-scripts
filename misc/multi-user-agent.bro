@load base/protocols/http
@load base/frameworks/sumstats
@load base/utils/time

module HTTP;

# A really simple "let's look for multiple user-agents per source IP address".
# Sometimes it catches malware, sometime it catches people with a lot of software installed on 
# their system. Either way it's an example on how to use SumStats.
#
# Tested on Bro 2.2
# Mike (sooshie@gmail.com)

export {
    redef enum Notice::Type += {
        # More than threshold unique user-agents in interval time
        Excessive_Unique_User_Agents
    };
    const unique_ua_threshold: double = 12 &redef;
    const unique_ua_interval = 12hrs &redef;
    # Set if you only want to look at outbound trafic, you must set Site::local_nets for this to be useful.
    const unique_ua_local_only: bool = T &redef;
}

# Setup the necessary stuff for SumStats to function
event bro_init()
    {
    local r1: SumStats::Reducer = [$stream="http-multi-ua", $apply=set(SumStats::UNIQUE), $unique_max=double_to_count(unique_ua_threshold)];
    SumStats::create([$name="http-multi-user-agent",
                      $epoch=unique_ua_interval,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                        {
                        return result["http-multi-ua"]$num+0.0;
                        },
                      $threshold=unique_ua_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["http-multi-ua"];
                        local message = fmt("%s had %d unique user-agetns in %s", key$host, r$num, duration_to_mins_secs(r$end-r$begin));
                        NOTICE([$note=HTTP::Excessive_Unique_User_Agents,
                                $src=key$host,
                                $msg=message,
                                $identifier=cat(key$host)]);
                        }]);
    }

# Look at each HTTP header, if it's the client and it's the user-agent header then we care about it.
# Extra flexibility to only pay attention to outbound requests vs. everybody probably scanning your
# web infrasructure.
event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( !is_orig )
        return;
    if ( name != "USER-AGENT" ) 
        return;

    if ( unique_ua_local_only && Site::is_local_addr(c$id$orig_h) )
        SumStats::observe("http-multi-ua", [$host=c$id$orig_h], [$str=value]);
        return;
    if ( !unique_ua_local_only ) 
        SumStats::observe("http-multi-ua", [$host=c$id$orig_h], [$str=value]);
    }
