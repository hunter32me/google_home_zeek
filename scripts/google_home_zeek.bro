##The DarkKnight watches your network even in the darkest of night and brigest of Days. 
module DNS;

export {
    redef enum Notice::Type += {
        DNS::LARGE_QUERY,
        DNS::LARGE_REPLY,
        DNS::DGA
    };

    const dns_query_max = 75;
    const dns_reply_max = 150;
    const dns_whitelist = /sophosxl.net|local/ ;
    const muticast_crap = 224.0.0.0/8;
    const muticast_crap_ipv6 = [ff02::]/16;

}

event bro_init()
{
    local r1 = SumStats::Reducer($stream="Detect.DGA", $apply=set(SumStats::SUM));
    SumStats::create([$name="Detect.DGA",
    $epoch=5min,
    $reducers=set(r1),
    $threshold=5.0,
    $threshold_val(key: SumStats::Key, result: SumStats::Result) =
    {
        return result["Detect.DGA"]$sum;
    },
    $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
    {
        local parts = split_string(key$str, /,/);
        NOTICE([$note=DNS::DGA,
        $resp_h=to_addr(parts[1]),$resp_p=to_port(parts[2])],
					$uid=parts[5],
					$msg=fmt("%s", parts[3]),
					$sub=fmt("%s", parts[4]),
					$identifier=cat(key$host,parts[2]),
					$suppress_for=5min
					]);
					}]);
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if (|query| > dns_query_max && dns_whitelist !in query)
    {
        NOTICE([$note=DNS::LARGE_QUERY, $conn=c, $msg=fmt("Holy DNS Query Batman : %s", query)]);
    }
}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
{
    if (len > dns_reply_max && c$id$resp_h !in muticast_crap && c$id$resp_h !in muticast_crap_ipv6 )
    {
        NOTICE([$note=DNS::LARGE_REPLY, $conn=c, $msg=fmt("Holy DNS Response Batman LEN: %s, DNS Response: %s", len, msg)]);
    }
}

