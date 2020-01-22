module DNS;
module TCP;

export {
    redef enum Notice::Type += {
        DNS::LARGE_QUERY,
        DNS::LARGE_REPLY
    };

    const dns_query_max = 75;
    const dns_reply_max = 100;
    const dns_whitelist = /sophosxl.net/;

}

event bro_init()
{
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if (|query| > dns_query_max && dns_whitelist !in query)
    {
        NOTICE([$note=DNS::LARGE_QUERY, $conn=c, $msg=fmt("Query: %s", query)]);
    }
}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
{
    if (len > dns_reply_max)
    {
        NOTICE([$note=DNS::LARGE_REPLY, $conn=c, $msg=fmt("Response: %s", dns_msg)]);
    }
}