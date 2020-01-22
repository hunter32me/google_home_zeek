module DNS;
module NTP;

export {
    redef enum Notice::Type += {
        DNS::LARGE_QUERY,
        DNS::LARGE_REPLY,
        NTP::MONLIST
    };

    const dns_query_max = 75;
    const dns_reply_max = 150;
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
        NOTICE([$note=DNS::LARGE_REPLY, $conn=c, $msg=fmt("DNS Response LEN: %s, DNS Response: %s", len, msg)]);
    }
}

event ntp_message(c: connection, msg: ntp_msg, excess: string)
{
    NOTICE([$note=NTP::MONLIST, $msg=fmt("NTP: %s", msg)]);
}