module dns_TXT_reply;

export {
    redef enum Log::ID += { LOG };
    type Info: record {
        ts:     time    &log;
        answer: string  &log;
    };
    redef enum Notice::Type += {
        DNS_TXT_Response
    };

}

event bro_init()
{
    Log::create_stream(dns_TXT_reply::LOG, [$columns=Info, $path="dns_TXT_reply"]);
}

event dns_TXT_reply (c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec, qtype: count)
{
    ## NOTICE([$note=Unknown_X509_Curve, $msg="ECC certificate with unknown curve; potential CVE-2020-0601 exploit attempt"]);
    if (qtype == "TXT") {
        NOTICE([$note=DNS_TXT_Response, $msg=fmt("Hey hi DNS TXT msg = %s", msg)]);
    }
}