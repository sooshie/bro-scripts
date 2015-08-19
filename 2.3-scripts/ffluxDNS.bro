###################################################################################
# Author: Seth Hall
# Update by: Brian Kellogg for Bro 2.3 - 12/9/2014
# Changed script from creating log file to raising notices.
#
# Description: Detect Fast Flux DNS requests.
# download and extract
#	 wget http://pkgs.fedoraproject.org/repo/pkgs/ntop/GeoIPASNum.dat.gz/24f082fa05a2bac804b664f6a0893aba/GeoIPASNum.dat.gz
# Place file extracted file in /usr/share/GeoIP/
#
# Needs to be documented
#
###################################################################################
@load base/frameworks/notice

module DNS;

type dns_fluxer: record {
        A_hosts: set[addr]; # set of all hosts returned in A replies
        ASNs: set[count]; # set of ASNs from A lookups
        score: double &default=0.0; # score for the fluxiness of the domain
        };

export {        
	redef enum Notice::Type += {
        	FastFlux,
        	};
        const flux_host_count_weight = 1.32 &redef;
        const flux_ASN_count_weight = 18.54 &redef;
        const flux_threshold = 142.38 &redef;
        const ff_false_positives = /\.ntp\.org$/ | /\.panthercdn\.com$/ | /\.clamav\.net$/ |
                                   /\.nyucd\.net$/ | /\.foxnews\.com$/ | /\.wired\.com$/ |
                                   /\.akamai.net$/ | /\.akadns\.net$/ | /\.akafms\.net$/ |
                                   /\.dcc-servers\.net$/ | /^chat\.freenode\.net$/ |
                                   /\.gentoo\.org$/ | /\.imageshack\.us$/ | /\.rizon\.(net|us)$/ |
                                   /^irc\.efnet\.org$/ &redef;
        # the string index is the query
        global detect_fast_fluxers: table[string] of dns_fluxer &synchronized; #this is cleaned up after the ttl by a scheduled task
        global fast_fluxers: set[string] &write_expire=1day &synchronized;
        }

function check_dns_fluxiness(query: string, c: connection, ans: dns_answer)
        {
        if ( query in detect_fast_fluxers )
                {
                local fluxer = detect_fast_fluxers[query];
                # +0 is to "cast" values to doubles
                local ASN_disparity = (|fluxer$ASNs|+0.0) / (|fluxer$A_hosts|+0.0);
                fluxer$score = ASN_disparity * ((flux_host_count_weight * |fluxer$A_hosts|) + (flux_ASN_count_weight * |fluxer$ASNs|));
                if ( fluxer$score > flux_threshold )
                        {
                        add fast_fluxers[query];
                        NOTICE([$note=FastFlux,
                                $msg=fmt("%.6f Flux score for %s is %f (%d hosts in %d distinct ASNs %f asns/ips)",
                                network_time(), query, fluxer$score, |fluxer$A_hosts|, |fluxer$ASNs|, ASN_disparity),
                                $sub=fmt("%s", ans), $conn=c], $suppress_for=1sec, $identifier=cat(c$id$orig_h,c$id$resp_h));
                        }
                }
        }

event delete_detect_fast_fluxers(query:string)
        {
        delete detect_fast_fluxers[query];
        }

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
        {
        if (ans$TTL > 30 mins || msg$num_answers < 4)
                return;

        local query = ans$query;
        # Don't keep any extra state about false positives
        if ( ff_false_positives in query )
                return;

        if ( query in detect_fast_fluxers )
                {
                local fluxer = detect_fast_fluxers[query];

                add fluxer$A_hosts[a];

                local asn = lookup_asn(a);
                add fluxer$ASNs[asn];
                check_dns_fluxiness(query, c, ans);
                }
        else
                {
                # It's a query that hasn't yet been seen
                local new_fluxer: dns_fluxer;
                detect_fast_fluxers[ans$query] = new_fluxer;

                # delete the element after the ttl is up with a little skew
                schedule ans$TTL + 1sec { delete_detect_fast_fluxers(query) };
                }
        }
