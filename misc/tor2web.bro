module TOR2Web;

# This is an easy way to look for several different ways to attempt to use TOR w/o going through TOR
# nodes. It looks for common domains associated with tor2web gateways. These can appear in DNS requests
# as well as HTTP requests. The SSL was added as a just-in-case. 2 TLDs used for TOR are also checked,
# however, seeing these outside the actual TOR network is/should be very rare to nonexistent.
#
# Tested on Bro 2.2
# Mike (sooshie@gmail.com)
#
# Tested on Bro 2.3
# Brian Kellogg

export {
    redef enum Notice::Type += { TOR2Web::HTTP, TOR2Web::DNS, TOR2Web::SSL };
    const tor2web_domains: set[string] = { "onion.to", "tor2web.org", "onion.lu", "anonym.to" } &redef;
    const tor_tlds: set[string] { "onion", "exit" } &redef;
}

# Last ditch effort to find t2w services on other domains
function onion_in_the_middle(domain: string): bool
    {
    if ( /\.onion\./ in domain )
        return T;
    return F;
    }

function get_2ld(domain: string): string
    {
    local result = find_last(domain, /\.[^\.]+\.[^\.]+$/);
    if ( result == "" )
        return domain;
    return sub_bytes(result, 2, |result|);
    }

function get_tld(domain: string): string
    {
    local result = find_last(domain, /\.[^\.]+$/);
    if ( result == "" )
        return domain;
    return sub_bytes(result, 2, |result|);
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( ! is_orig )
        return;
    if ( name == "HOST" )
        {
        local domain = get_2ld(value);
        local tld = get_tld(value);
        if ( ( domain in tor2web_domains ) || ( tld in tor_tlds ) || onion_in_the_middle(value) )
            {
            NOTICE([$note=TOR2Web::HTTP, $msg="Found TOR2Web Hostname",
                    $sub=value, $conn=c, $suppress_for=30mins, 
                    $identifier=cat(c$id$resp_h,c$id$resp_p,c$id$orig_h,value)]);
            return;
            }
        }
    }

hook DNS::do_reply(c: connection, msg: dns_msg, ans: dns_answer, reply: string)
    {
    local dyn = F;
    local value: string;
    if ((c?$dns) && (c$dns?$query))
        { 
        local domain = get_2ld(c$dns$query);
        local tld = get_tld(c$dns$query);
        if ( ( domain in tor2web_domains ) || ( tld in tor_tlds ) || onion_in_the_middle(c$dns$query) )
            {
            NOTICE([$note=TOR2Web::DNS, $msg="Found TOR2Web Hostname",
                    $sub=c$dns$query, $conn=c, $suppress_for=30mins, 
                    $identifier=cat(c$id$resp_h,c$id$resp_p,c$id$orig_h,c$dns$query)]);
            return;
            }
        }
    }

event ssl_established(c: connection)
{
    if(c$ssl?$server_name) 
        {
        local domain = get_2ld(c$ssl$server_name);
        local tld = get_tld(c$ssl$server_name);
        if ( ( domain in tor2web_domains ) || ( tld in tor_tlds ) || onion_in_the_middle(c$ssl$server_name) )
            {
            NOTICE([$note=TOR2Web::SSL, $msg="Found TOR2Web Hostname",
                    $sub=c$ssl$server_name, $conn=c, $suppress_for=30mins, 
                    $identifier=cat(c$id$resp_h,c$id$resp_p,c$id$orig_h,c$ssl$server_name)]);
            return;
            }
        }
}
