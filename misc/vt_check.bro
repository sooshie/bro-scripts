@load base/files/extract
@load base/files/hash

module VTCHECK;

# This will do a hash check aginst VT for specified file-types
# if the Virustotal produces a result, it will create a NOTICE entry with the 
# number of AV engines that flagged as well as any sample results
#
# Mike (sooshie@gmail.com)
#
# Now with more API usage!
#
# for files that don't exist in VT, this script will cause an error similar to: 
# rm: cannot remove `<sha256>.txt': No such file or directory
# You can probably ignore these w/o out issue/problems

export {
        const check_file_types: set[string] = {
                "application/x-dosexec",
                "application/x-executable",
        } &redef;

        const curl: string = "/usr/bin/curl" &redef;
        const url: string = "https://www.virustotal.com/vtapi/v2/file/report";
        const user_agent = "Bro VirusTotal Checker (thanks for being awesome)"  &redef;

        const vt_apikey = "" &redef;

        redef enum Notice::Type += { VirusTotal::Result };
}

global checked_hashes: set[string] &synchronized;

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( meta?$mime_type && meta$mime_type in check_file_types )
        {
        Files::add_analyzer(f, Files::ANALYZER_SHA256);
        }
    }

event file_state_remove(f: fa_file)
    {
    if ( ! f?$info ) return;

    if ( f$info?$sha256 && ! ( f$info$sha256 in checked_hashes ) )
        {
        add(checked_hashes[f$info$sha256]);
        local bodyfile = fmt("%s.txt", f$info$sha256);
        when ( local result = Exec::run([$cmd=fmt("%s -k -A \"%s\" -o \"%s\" -d resource=%s -d apikey=%s \"%s\"", 
                                         curl, user_agent, bodyfile, f$info$sha256, vt_apikey, url), 
                                         $read_files=set(bodyfile)]) )
            {
            if ( result?$files && bodyfile in result$files )
                {
                local body = fmt("%s", result$files[bodyfile]);
                local context = "";
                local subcon = "-";
                if ( |body| > 0 )
                    {
                    local positives: string;
                    local total: string;
                    local elements = split_string(body, /,/);
                    local results: vector of string;
                    for ( e in elements )
                        {
                        local temp: string_vec;
                        if ( /\"positives\":/ in elements[e] )
                            {
                            temp = split_string(elements[e], /:/);
                            positives = sub_bytes(temp[2], 2, |temp[2]|);
                            }
                        else if ( /\"total\":/ in elements[e] )
                            {
                            temp = split_string(elements[e], /:/);
                            total = sub_bytes(temp[2], 2, |temp[2]|);
                            }
                        else if ( /\"result\":/ in elements[e] )
                            {
                            if ( ! ( / null/ in elements[e] ) )
                                {
                                temp = split_string(elements[e], /\"/);
                                #print temp[4];
                                results[|results|] = temp[4];
                                }
                            }
                        }
                    context =  fmt("%s out of %s flagged as positive", positives, total);
                    subcon = join_string_vec(results, ",");
                    if ( ! ( context == "" ) )
                        {
                        local id: conn_id;
                        local c: connection;
                        local uid: string;
                        for ( conn in f$conns )
                            id = conn;
                        for ( u in f$info$conn_uids )
                            uid = u;
                        c$id = id;
                        c$uid = uid;
                        NOTICE([$note=VirusTotal::Result, $msg=context, $sub=subcon, $conn=c]);
                        }
                    }
                }
            }
        }
    }
