module DNS;

export {
    redef enum Notice::Type += {
        DNS::LARGE_QUERY
    };

    const dns_query_max = 200;

}

event bro_init()
{
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if (|query| > dns_query_max)
    {
        NOTICE([$note=DNS::LARGE_QUERY, $conn=c, $msg=fmt("Query: %s", query)]);
    }
}