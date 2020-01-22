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

event dns_A_reply (c: connection, msg: dns_msg, ans: dns_answer, a: addr)
{
    
}