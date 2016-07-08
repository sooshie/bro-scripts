This module is used to look for dynamic dns domains that are present in various kinds of
network traffic. For HTTP, the HOST header value is checked, for DNS the query request value
is checked, and for SSL the server value is checked. Since dynamic DNS domains often take
the format of <user defined>.domain.tld the value in the host header is stripped of everything 
to the left of domain.tld, in the event that doesn't match the check is expanded to 
something.domain.tld.

A good place to get started is malware-domains dyndns list, the following will put it in the 
right format for this script:
```
wget "http://www.malware-domains.com/files/dynamic_dns.zip" && unzip -c dynamic_dns.zip | tail -n +4 | grep -v ^# | grep -v ^$ | cut -f 1 > tmp.txt && echo -e "#fields\tdomain" > dynamic_dns.txt && cat tmp.txt | cut -d '#' -f 1 >> dynamic_dns.txt && rm tmp.txt dynamic_dns.zip
```

OR if that file is not available a somewhat recent copy is included with this script (in origial form). To clean it up for use with Bro, do the following:
```
cat dynamic_dns.txt | grep -v ^# | grep -v ^$ | cut -f 1 > tmp.txt && echo -e "#fields\tdomain" > dynamic_dns.txt && cat tmp.txt | cut -d '#' -f 1 >> dynamic_dns.txt && rm tmp.txt
```

In additon to looking for the presence of dynamic DNS domains it will keep track (for 1 day)
all IPs that resolve to a dynamic DNS domain, and flag any traffic destined to those IP addresses

Requires Bro 2.4
Mike (sooshie@gmail.com)
