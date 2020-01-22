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

    const = dns_query_max = 200l

}

event bro_init()
{
    Log::create_stream(dns_TXT_reply::LOG, [$columns=Info, $path="dns_TXT_reply"]);
}

eevent dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if (|query| > dns_query_max)
    {
        NOTICE([$note=DNS_LARGE_QUERY, $conn=c, $msg=fmt("Query: %s, Query_type: %s", query, qtype)])
    }
}