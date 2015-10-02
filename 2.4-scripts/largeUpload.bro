#
# Author: Brian Kellogg
# This script alerts on any large uploads to the Internet
# and emails alerts on sufficiently large uploads if enabled.
#

module test;

# add custom notice types
redef enum Notice::Type += {
        Large_Outgoing_Tx,
        Very_Large_Outgoing_Tx,
        Multiple_Large_Outgoing_Tx,
};

# Create a set of domain suffixes that should be ignored for any notices.
global ignore_domains = set(".test.net", ".amazon.com");
global vpn_nets = set(172.16.0.0/24, 192.168.1.1/24);
# Create an empty pattern where we're going to automatically create.
global my_domain_suffixes = /MATCH_NOTHING/; # There is bug with setting blank patterns at the moment.

const maxTx = 15000000;          # single conn Tx bytes over which we want to alert on immediately
const recordTx = 1000000;        # destination hosts to record if over this many bytes
const maxNumUp = 13;              # number of large uploads per IP before an email is generated for that IP

# table indexed by source IP of hosts that have triggered notices and/or emails
# if the number of large uploads exceed maxNumup then generate email
# expire table's entry for IP if older than 1 days
global susOrigs: table[addr] of count &default=0 &create_expire=1days;

# table indexed by dest IP of hosts that have had large uploads to them
# if the number of large uploads exceed maxNumup then generate email
# expire table's entry for IP if older than 1 days
global susResps: table[addr] of count &default=0 &create_expire=1days;

event bro_init() &priority=10
        {
        # Create the my_domain_suffixes pattern by auto constructing it from the ignore_domains set.
        my_domain_suffixes = set_to_regex(ignore_domains, "(\\.?|\\.)(~~)$");
        }

#
# Send email if Very_Large_Outgoing_Tx or Multiple_Large_Outgoing_Tx notice type is generated
#
#hook Notice::policy(n: Notice::Info)
#    {
#    if (n$note == Very_Large_Outgoing_Tx || n$note == Multiple_Large_Outgoing_Tx)
#               add n$actions[Notice::ACTION_EMAIL];
#    }


#
# Alert on potential compromised internal hosts ex-filtrating data
#
# event fires in Bro upon connection state being removed from memory
event connection_state_remove(c: connection)
        {
        local endTime: time;    # used to calculate Tx end time by adding duration to the Tx start time

        # if number of bytes uploaded to Inet is over recordTx in size then continue
        if (c$orig$num_bytes_ip > recordTx)
                {
                # check to see if orig IP is an internal IP
                if (!Site::is_local_addr(c$id$orig_h))
                        return;

                # check to see if dest ip is not an internal IP and also not a VPN client
                if ((Site::is_local_addr(c$id$resp_h)) && (!(c$id$resp_h in vpn_nets)))
                        return;

                # use when to create a non-blocking (asynchronous) reverse DNS query for resp IP
                when (local dst = lookup_addr(c$id$resp_h))
                        {
                        # check for sites that we know will have legit large uploads to
                        if (my_domain_suffixes in dst)
                                return;

                        # calculate when the Tx ended
                        endTime = c$start_time + c$duration;
                        # keep track of how many large uploads were sent to this host
                        susResps[c$id$resp_h]+=1;
                        # if num_bytes sent over certain size then send an email alert else just raise a notice log entry
                        if (susResps[c$id$resp_h] >= maxNumUp)
                                {
                                # raise notice msg and format the time stamp for the sub message so that it is human readable
                                NOTICE([$note=Multiple_Large_Outgoing_Tx, 
					$msg=fmt("Dest received multiple large uploads from internal IP(s).  Dest name %s.", dst), 
					$sub=fmt("Tx start: %s UTC, end: %s UTC", strftime("%m/%d/%Y %H:%M:%S", c$start_time), 
					strftime("%m/%d/%Y %H:%M:%S", endTime)), $conn=c, $suppress_for=480mins, 
					$identifier=cat(c$id$resp_h)]);
                                }

                        # now lookup orig IP DNS record
                        when (local src = lookup_addr(c$id$orig_h))
                                {
                                # keep track of how many large uploads originated from this host
                                susOrigs[c$id$orig_h]+=1;
                                # if number of large uploads over certain size then send an email alert else just raise a notice log entry
                                if (susOrigs[c$id$orig_h] >= maxNumUp)
                                        {
                                        # raise notice msg and format the time stamp for the sub message so that it is human readable
                                        NOTICE([$note=Multiple_Large_Outgoing_Tx, 
						$msg=fmt("Orig Txed multiple large uploads.  Source name %s.", src), 
						$sub=fmt("Tx start: %s UTC, end: %s UTC", 
						strftime("%m/%d/%Y %H:%M:%S", c$start_time), strftime("%m/%d/%Y %H:%M:%S", endTime)), 
						$conn=c, $suppress_for=480mins, $identifier=cat(c$id$orig_h)]);
                                        }

                                # if num_bytes sent over certain size then send an email alert else just raise a notice log entry
                                if (c$orig$num_bytes_ip > maxTx)
                                        {
                                        # raise notice msg and format the time stamp for the sub message so that it is human readable
                                        NOTICE([$note=Very_Large_Outgoing_Tx, 
						$msg=fmt("Orig transmitted %d bytes to resp.  Duration %s sec.  Source is %s.  Destination is %s.  Connection UID %s.", 
						c$orig$num_bytes_ip, c$duration, src, dst, c$uid), 
						$sub=fmt("Tx start: %s UTC, end: %s UTC", strftime("%m/%d/%Y %H:%M:%S", c$start_time), 
						strftime("%m/%d/%Y %H:%M:%S", endTime)), $conn=c]);
                                        }
                                else
                                        {
                                        # raise notice msg and format the time stamp for the sub message so that it is human readable
                                        NOTICE([$note=Large_Outgoing_Tx, 
						$msg=fmt("Orig transmitted %d bytes to resp.  Duration %s sec.  Source is %s.  Destination is %s.  Connection UID %s.", 
						c$orig$num_bytes_ip, c$duration, src, dst, c$uid), 
						$sub=fmt("Tx start: %s UTC, end: %s UTC", 
						strftime("%m/%d/%Y %H:%M:%S", c$start_time), strftime("%m/%d/%Y %H:%M:%S", endTime)), $conn=c]);
                                        }
                                }
                        }
                }
        return;
        }
