@load base/files/extract
@load base/files/hash

module VTCHECK;

# This will do a hash check aginst VT for specified file-types
# if the Virustotal produces a result, it will create a NOTICE entry with the 
# number of AV engines that flagged as well as any sample results
#
# Mike (sooshie@gmail.com)
#
# Thanks VT for having a somewhat scrapable-site!
# Please don't abuse them
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
        #https://www.virustotal.com/en/file/35153c65e2e5a56a04d8642f391ef0e657181bfe99b3b759c1765a4b49e5acb5/analysis/
        const url: string = "https://www.virustotal.com/en/file";
        const user_agent = "Bro VirusTotal Checker (thanks for being awesome)"  &redef;

        redef enum Notice::Type += { VirusTotal::Result };
}

global checked_hashes: set[string] &synchronized;

event file_new(f: fa_file)
    {
    if ( f?$mime_type && f$mime_type in check_file_types )
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
        when ( local result = Exec::run([$cmd=fmt("%s -k -A \"%s\" -o \"%s\" \"%s/%s/analysis/\"", curl, user_agent, bodyfile, url, f$info$sha256), 
                                         $read_files=set(bodyfile)]) )
            {
            if ( result?$files && bodyfile in result$files )
                {
                local body = fmt("%s", result$files[bodyfile]);
                if ( |body| > 0 )
                    {
                    local one = find_all(body, /[0-9]+ out of [0-9]+ antivirus/);
                    local context = "";
                    local subcon = "-";
                    if ( |one| > 0 )
                        for ( r in one )
                            context = r;
                    # kind of hacky, but it seems to work well-enough for now
                    if ( /Some of the detections were/ in body )
                        { 
                        one = find_all(fmt("%s", body), /Some of the detections were: [\/A-Za-z0-9.:!,\(\) _-]+   /);
                        if ( |one| > 0 )
                            for ( r in one )
                                subcon = sub_bytes(r, 1, |r| - 4);
                        }
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
