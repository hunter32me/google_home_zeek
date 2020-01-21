module dns_TXT_reply;

export {
    redef enum Log::ID += { LOG };
    type Info: record {
        ts:     time    &log;
        answer: string  &log;
    };
}

event bro_init()
{
    Log::create_stream(dns_TXT_reply::LOG, [$columns=Info, $path="dns_TXT_reply"]);
}

event dns_TXT_reply (c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec)
{
    NOTICE($note=DNS_TXT_Response, $msg="DNS TEXT Answer")
    Log::write(DNS_Txt_reply::LOG, Info($ts=network_time(), $answer=ans))
}