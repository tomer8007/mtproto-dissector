-- Telegram MTProto Dissector for Wireshark

local telegram_proto = Proto("MTProto", "Telegram MTProto Dissector")

local src_ipv4 = Field.new("ip.src")
local dst_ipv4 = Field.new("ip.dst")

local tcp_syn_flag = Field.new("tcp.flags.syn")
local tcp_ack_flag = Field.new("tcp.flags.ack")
local tcp_initial_rtt = Field.new("tcp.analysis.initial_rtt")
local tcp_len = Field.new("tcp.len")
local tcp_seq_num = Field.new("tcp.seq")
local tcp_seq_num_raw = Field.new("tcp.seq_raw")
local tcp_payload_field = Field.new("tcp.payload")
local tcp_segments = Field.new("tcp.segments")
local tcp_segment_count = Field.new("tcp.segment.count")
local tcp_reassembled_length = Field.new("tcp.reassembled.length")
local tcp_reassembled = Field.new("tcp.reassembled.data")


-- Define fields

local obfuscated_traffic_   = ProtoField.new("Obfuscated data", "mtproto.obfuscated", ftypes.BYTES)
local continued_traffic_    = ProtoField.new("Continued data", "mtproto.continued", ftypes.BYTES)

-- obfuscation fields
local random_bytes_         = ProtoField.new("Random Bytes", "mtproto.random", ftypes.BYTES)
local init_payload_         = ProtoField.new("Initialization payload", "mtproto.initpayload", ftypes.BYTES)
local enc_msg_              = ProtoField.new("Obfuscated payload", "mtproto.obfpayload", ftypes.BYTES)
local enc_fields_           = ProtoField.new("Encrypted fields", "mtproto.encfields", ftypes.BYTES)
local enc_obf_key_          = ProtoField.new("Outgoing Obfuscation Key [AES CTR 128]", "mtproto.enckey", ftypes.BYTES)
local enc_obf_iv_           = ProtoField.new("Outgoing Obfuscation IV [AES CTR 128]", "mtproto.enckey", ftypes.BYTES)
local deobfuscated_traffic_ = ProtoField.new("Deobfuscated data", "mtproto.deobfuscated", ftypes.BYTES)
local protocol_type_        = ProtoField.uint32 ("mtproto.protocol"  , "Protocol Type"     , base.HEX)
local dc_id_                = ProtoField.int32 ("mtproto.dcid"  , "DC Identifier (optional; for MTProxy)"     , base.DEC)

local short_protocol_indicator_         = ProtoField.uint8 ("mtproto.abridged_indicator"  , "Short Protocol Indicator"     , base.HEX) 
local long_protocol_indicator_          = ProtoField.uint32 ("mtproto.protocolindicator"  , "Protocol Indicator"     , base.HEX) 

-- abridged transport protocol fields
local length_                   = ProtoField.uint32 ("mtproto.length"  , "MTProto frame length (in multiples of 4)"     , base.DEC)
local length_ext_               = ProtoField.uint32 ("mtproto.lengthext"  , "MTProto frame length, extended (in multiples of 4)"     , base.DEC)
local quickac_token_            = ProtoField.uint32 ("mtproto.quickack"  , "Quick-Ack Token"     , base.HEX)
local flag_quickackreq          = ProtoField.bool("mtproto.quickackreq", "Quick-Ack Request", 8, {"This message expects a quick-ack", "This message does NOT expect a quick-ack"}, 128)

-- Full transport protocol fields
local full_length_          = ProtoField.uint32 ("mtproto.fulllength"  , "MTProto Frame Length (including headers)"     , base.DEC)
local full_seqno_           = ProtoField.uint32 ("mtproto.frameseqno"  , "Frame Sequence Number"     , base.DEC)
local crc32_                = ProtoField.uint32 ("mtproto.crc32"  , "Frame CRC32"     , base.HEX)

-- Intermediate transport protocol fields
local intermediate_length_        = ProtoField.uint32 ("mtproto.intermediatelength"  , "MTProto Frame Length"     , base.DEC)


local mtproto_payload_      = ProtoField.new("MTProto frame", "mtproto.frame", ftypes.BYTES)
local frame_error_code_     = ProtoField.int32("mtproto.errorcode", "Error Code", base.DEC)
local auth_key_id_          = ProtoField.new("Auth Key ID", "mtproto.authkeyid", ftypes.BYTES)
local msg_id_               = ProtoField.uint64 ("mtproto.msgid"  , "Message ID"     , base.HEX)
local msg_id_timestamp_     = ProtoField.uint32("mtproto.timestamp", "Unix Timestamp", base.DEC)
local msg_id_fraction_      = ProtoField.uint32("mtproto.timefraction", "Time fraction", base.HEX, nil, 0xFFFFFFF0)
local msg_id_flags_         = ProtoField.uint32("mtproto.msgidflags", "Flags", base.DEC, {[0] = "This is a client message", [1] = "This message is a response to a client message", [2] = "INVLIAD", [3]= "This message is NOT a response to client message"}, 0x3)
local frame_padding_        = ProtoField.new("Padding", "mtproto.framepadding", ftypes.BYTES)

local msg_key_              = ProtoField.new("Message Key", "mtproto.msgkey"  , ftypes.BYTES)
local message_length_       = ProtoField.uint32 ("mtproto.messagelength"  , "Message Length"     , base.DEC)
local message_type_         = ProtoField.uint32 ("mtproto.messagetype"  , "Message Type"     , base.HEX)
local encrypted_message_    = ProtoField.new("Encrypted message", "mtproto.encryptedmessage", ftypes.BYTES)
local decrypted_message_    = ProtoField.new("Decrypted message", "mtproto.decryptedmessage", ftypes.BYTES)
local inner_message_        = ProtoField.new("Message", "mtproto.innermessage", ftypes.BYTES)
local plain_message_        = ProtoField.new("MTProto Message", "mtproto.message", ftypes.BYTES)
local rpc_result_message_   = ProtoField.new("RPC Result Message", "mtproto.rpcresmessage", ftypes.BYTES)

-- inner decrypted message fields
local salt_                 = ProtoField.uint64 ("mtproto.salt"  , "Salt"     , base.HEX)
local session_id_           = ProtoField.uint64 ("mtproto.sessionid"  , "Session ID"     , base.HEX)
local msg_id_enc_           = ProtoField.uint64 ("mtproto.msgid_enc"  , "Message ID"     , base.HEX)
local seq_no_               = ProtoField.uint32 ("mtproto.seqno"  , "Sequence Number"     , base.HEX)
local seq_no_value_         = ProtoField.uint32("mtproto.seqnoval", "Sequence Number Value", base.DEC, nil, 0xFFFFFFFE)
local flag_contentmsg_      = ProtoField.bool("mtproto.contentmsg", "Is Content-Related Message", 32, {"This IS a content message. It MUST be acknowledged", "This is NOT a content message (no ack required)"}, 0x1)
local message_data_length_  = ProtoField.uint32 ("mtproto.msgdatalen"  , "Message Data Length"     , base.DEC)
local message_data_         = ProtoField.new("Message Data", "mtproto.msgdata", ftypes.BYTES)
local inner_padding_        = ProtoField.new("Inner Message Padding", "mtproto.msgpadding", ftypes.BYTES)

-- we define these as a protocol fields to avoid auto-expansion in the GUI and allow filtering
local tl_field_             = ProtoField.new("TL field", "mtproto.tlfield", ftypes.BYTES) 
local flags_tl_field_       = ProtoField.uint32 ("mtproto.flagsfield"  , "Flags field"     , base.HEX)
local bytes_tl_field_       = ProtoField.new("Bytes field", "mtproto.bytesfield", ftypes.BYTES) 
local vector_tl_field_      = ProtoField.new("Vector field", "mtproto.vectorfield", ftypes.BYTES) 
local complex_tl_field_     = ProtoField.new("Complex field", "mtproto.complexfield", ftypes.BYTES) 
local complex_type_constructor_ = ProtoField.uint32 ("mtproto.typeconstructor"  , "Type Constructor"     , base.HEX)

local rpc_result_req_msg_id_        = ProtoField.uint64 ("mtproto.rpcres.reqmsgid"  , "Request Message ID"     , base.HEX)

local response_in_frame_            = ProtoField.framenum("mtproto.response_in", "Response In Frame", base.NONE, frametype.RESPONSE)
local request_in_frame_             = ProtoField.framenum("mtproto.request_in", "Request In Frame", base.NONE, frametype.REQUEST)
local ack_in_frame_                 = ProtoField.framenum("mtproto.ack_in", "Acknowledgment In Frame", base.NONE, frametype.RESPONSE)
local msg_in_frame_                 = ProtoField.framenum("mtproto.msg_in", "Message In Frame", base.NONE, frametype.REQUEST)



-- Options
telegram_proto.prefs.api_layer  =    Pref.uint("API level", 220, "The Telegram API level the scema will load for")
telegram_proto.prefs.auth_key_1 =    Pref.string("Auth Key #01  (2048-bit hex)", "", "A 2048-bit auth_key (result of DH) formatted as a hex string")
telegram_proto.prefs.auth_key_2 =    Pref.string("Auth Key #02  (2048-bit hex)", "", "A 2048-bit auth_key (result of DH) formatted as a hex string")
telegram_proto.prefs.auth_key_3 =    Pref.string("Auth Key #03  (2048-bit hex)", "", "A 2048-bit auth_key (result of DH) formatted as a hex string")
telegram_proto.prefs.auth_key_4 =    Pref.string("Auth Key #04  (2048-bit hex)", "", "A 2048-bit auth_key (result of DH) formatted as a hex string")
telegram_proto.prefs.auth_key_5 =    Pref.string("Auth Key #05  (2048-bit hex)", "", "A 2048-bit auth_key (result of DH) formatted as a hex string")
telegram_proto.prefs.auth_key_6 =    Pref.string("Auth Key #06  (2048-bit hex)", "", "A 2048-bit auth_key (result of DH) formatted as a hex string")
telegram_proto.prefs.auth_key_7 =    Pref.string("Auth Key #07  (2048-bit hex)", "", "A 2048-bit auth_key (result of DH) formatted as a hex string")
telegram_proto.prefs.auth_key_8 =    Pref.string("Auth Key #08  (2048-bit hex)", "", "A 2048-bit auth_key (result of DH) formatted as a hex string")
telegram_proto.prefs.auth_key_9 =    Pref.string("Auth Key #09  (2048-bit hex)", "", "A 2048-bit auth_key (result of DH) formatted as a hex string")
telegram_proto.prefs.auth_key_10 =    Pref.string("Auth Key #10  (2048-bit hex)", "", "A 2048-bit auth_key (result of DH) formatted as a hex string")
telegram_proto.prefs.auth_key_11 =    Pref.string("Auth Key #11  (2048-bit hex)", "", "A 2048-bit auth_key (result of DH) formatted as a hex string")
telegram_proto.prefs.auth_key_12 =    Pref.string("Auth Key #12  (2048-bit hex)", "", "A 2048-bit auth_key (result of DH) formatted as a hex string")



local script_path = debug.getinfo(1, "S").source:sub(2):match("(.*[/\\])")
local json = require('json')

-- Expert info
local expert_info_incomplete_parsing = ProtoExpert.new("mtproto.incompleteparsing", "Incomplete parsing, encountered unknown type(s). Wrong API level?", expert.group.COMMENTS_GROUP, expert.severity.WARN)

telegram_proto.fields = {
    obfuscated_traffic_, deobfuscated_traffic_, continued_traffic_, 
    random_bytes_, enc_obf_key_, enc_obf_iv_, init_payload_, enc_msg_, enc_fields_, protocol_type_, dc_id_,
    short_protocol_indicator_, long_protocol_indicator_,
    mtproto_payload_, length_, length_ext_, frame_error_code_, quickac_token_, flag_quickackreq, -- abridged transport
    intermediate_length_, -- intermediate transport
    full_length_, full_seqno_, crc32_, -- full transport
    auth_key_id_, msg_id_, msg_id_timestamp_, msg_id_fraction_, msg_id_flags_, frame_padding_, msg_key_, message_length_, message_type_, 
    encrypted_message_, decrypted_message_, plain_message_, inner_message_, rpc_result_message_,
    tl_field_, bytes_tl_field_, vector_tl_field_, complex_tl_field_, complex_type_constructor_, flags_tl_field_,
    salt_, session_id_, msg_id_enc_, seq_no_, seq_no_value_, flag_contentmsg_, message_data_length_, message_data_, inner_padding_,
    rpc_result_req_msg_id_,
    request_in_frame_, response_in_frame_, ack_in_frame_, msg_in_frame_
}
telegram_proto.experts = {expert_info_incomplete_parsing}

-- read mtproto schema

local mtprpto_schema_file = io.open(script_path .. "schema\\mtproto_tl_schema.json", "rb")
local mtproto_schema_json, err = mtprpto_schema_file:read("*all")
local mtproto_schema = json.decode(mtproto_schema_json)
mtprpto_schema_file:close()

local tl_type_map = {}
local api_schema = {}
local loaded_layer = telegram_proto.prefs.api_layer -- will be loaded later in the file


local _protocol_type = Field.new("mtproto.protocol")
local _length = Field.new("mtproto.length")
local _lengthext = Field.new("mtproto.lengthext")


-- Table to track TCP state for each connection
local connection_infos = {}

local msg_ids_to_packet_numbers = {}
local msg_ids_to_ack_packet_numbers = {}
local req_msg_ids_to_res_frame = {}
local next_expected_pdu_length = 0


-- Known Telegram IPs (partial list)
-- TODO: detect by IP range
local telegram_ips = {
    -- ["149.154.165.133"] = true, -- cdn4.telesco.pe
    ["149.154.167.41"] = true,
    ["149.154.167.43"] = true,
    ["149.154.167.50"] = true,
    ["149.154.167.51"] = true,
    ["149.154.167.91"] = true,
    ["149.154.167.92"] = true,
    --["149.154.167.99"] = true, -- td.telegram.org (update server, over TLS) + other domains
    ["149.154.167.151"] = true,
    ["149.154.167.222"] = true,
    -- ["149.154.171.236"] = true, -- cdn5.telesco.pe
    ["149.154.175.53"] = true,
    ["149.154.175.54"] = true,
    ["149.154.175.56"] = true,
    ["149.154.175.59"] = true,
    ["149.154.175.100"] = true,
    ["91.108.4.0"] = true,
    ["91.108.4.1"] = true,
    ["91.108.56.183"] = true
}

-- Known MTProto ports
local telegram_ports = {
    [443] = true,
    [80] = true,
    [5222] = true,
    [2396] = true
}

-- Dissector function
function telegram_proto.dissector(buffer, pinfo, tree)
    local src_ip = tostring(src_ipv4())
    local dst_ip = tostring(dst_ipv4())
    local src_port = pinfo.src_port
    local dst_port = pinfo.dst_port

    local offset = 0

    -- Check if IP and Port match known Telegram patterns
    local is_telegram_ip = telegram_ips[src_ip] or telegram_ips[dst_ip]
    local is_telegram_port = telegram_ports[src_port] or telegram_ports[dst_port]

    print("-- MTProto dissector got called for packet " .. pinfo.number .. " --")

    if not is_telegram_port or not is_telegram_ip then
        return
    end

    pinfo.cols.protocol = "MTProto"
    local subtree = tree:add(telegram_proto, buffer(), "Telegram Messanger MTProto Protocol")

    local seen_tcp_handshake = tcp_initial_rtt() ~= nil
    local is_outgoing = telegram_ips[dst_ip] ~= nil

    -- Get connection identifiers
    local connection_key = get_normalized_connection_key(pinfo)

    if connection_infos[connection_key] == nil then
        -- new connection
        local connection_info = {}
        connection_info.out_packets = {}
        connection_info.in_packets = {}
        connection_infos[connection_key] = connection_info
    end

    local is_initialize_packet = false
    local is_first_out_packet_in_conn = tcp_seq_num()() == 1 and is_outgoing

    if is_first_out_packet_in_conn and seen_tcp_handshake then
        is_initialize_packet = true
    elseif is_first_out_packet_in_conn and not seen_tcp_handshake then
        -- is it a mid-session packet or a real start of a session?
        local looks_like_init_data = looks_like_valid_init_payload(buffer, offset)

        is_initialize_packet = looks_like_init_data
    end

    local tcp_payload = tcp_payload_field()
    local tcp_payload_start = tcp_payload.offset -- ← this is the key!
    local relative_tcp_offset = buffer:offset() - tcp_payload_start  -- in case of multiple protocol layers, tells you the offset to this layer

    print("Tcp seq num is " .. tostring(tcp_seq_num()))

    local is_multi_layer = tcp_segment_count() ~= nil

    local connection_info = connection_infos[connection_key]

    -- create packet context if needed
    local packet_key = get_packet_key()
    local packets_array_key = is_outgoing and "out_packets" or "in_packets"
    if connection_info[packets_array_key][packet_key] == nil then
        connection_info[packets_array_key][packet_key] = {}
    end

    if is_initialize_packet then
        --
        -- First outgoing packet, so parse the initializaiton payload
        --

        -- check the first dword, see if it's obfuscated\not-obfuscated\HTTP
        local is_obfuscated, detected_protocol = detect_transport_protocol(buffer, offset)
        connection_info.protocol = detected_protocol
        connection_info.is_obfuscated = is_obfuscated

        connection_info.out_first_tcp_seq_num = tcp_seq_num_raw()()

        print("connection_info.is_obfuscated  =" .. tostring(connection_info.is_obfuscated ))

        if detected_protocol == "http" then
            -- first packet of http, so call the http dissector
            return Dissector.get("http"):call(buffer, pinfo, tree)
        end

        if not is_multi_layer then
            if is_outgoing then 
                pinfo.cols.info = "Client ➜ Server: "
            else
                pinfo.cols.info = "Server ➜ Client: "
            end
        end

        if detected_protocol == "abridged" and not is_obfuscated and buffer:len() == 1 then
            append_pinfo_string(pinfo, "Transport protocol indicator")
            subtree:append_text(", Abridged transport protocol indicator")
            subtree:add_le(short_protocol_indicator_, buffer(offset, 1)):append_text(" [Abridged]"); offset = offset + 1
        elseif detected_protocol == "intermediate" then
            append_pinfo_string(pinfo, "Transport protocol indicator")
            subtree:append_text(", Intermediate transport protocol indicator")
            subtree:add_le(long_protocol_indicator_, buffer(offset, 4)):append_text(" [Intermediate]"); offset = offset + 4
        elseif detected_protocol == "padded_intermediate" then
            append_pinfo_string(pinfo, "Transport protocol indicator")
            subtree:append_text(", Padded Intermediate transport protocol indicator")
            subtree:add_le(long_protocol_indicator_, buffer(offset, 4)):append_text(" [Padded Intermediate]"); offset = offset + 4
        elseif connection_info.protocol == nil then
            -- We couldn't detect this exact protocol;
            -- We don't have obfuscation information; 
            -- It's the first init packet
            -- likely an unknown\unsupport protocol
            append_pinfo_string(pinfo, "Unknown data")
            subtree:append_text(", Unknown data")
            return
        end

        if connection_info.is_obfuscated then
            local obfuscated_traffic_tree = subtree:add(obfuscated_traffic_, buffer(offset))
            offset = dissect_ofbuscation_init_payload(pinfo, obfuscated_traffic_tree, buffer, offset, subtree, connection_key)
            
            subtree:append_text(", Obfuscated initialization packet")
        else
            -- not obfuscated? try to read the initial packet just like other packets
            local info = ""; local frames_count = 0
            offset, frames_count, info = dissect_mtproto_frames(pinfo, subtree, connection_info, buffer, offset, 0, is_outgoing)

            append_pinfo_string(pinfo, info)

            if connection_info.protocol == "full" then
                subtree:append_text(", Full-Tranport")
            end
        end

        pinfo.cols.info = tostring(pinfo.cols.info) .. " [init connection]"


    elseif connection_info ~= nil then
        --
        -- not first packet, known connection
        --

        if tcp_seq_num()() == 1 and not is_outgoing then
            -- first incoming packet in connection
            if connection_info.in_first_tcp_seq_num == nil then
                connection_info.in_first_tcp_seq_num = tcp_seq_num_raw()()
            end
        end

        if not is_multi_layer then
            if is_outgoing then 
                pinfo.cols.info = "Client ➜ Server: "
            else
                pinfo.cols.info = "Server ➜ Client: "
            end
        end

        if connection_info.protocol == nil then
            -- We couldn't detect this exact protocol;
            -- We don't have obfuscation information; 
            -- this is likely a mid-session obfuscated packet with no handshake info
            local continued_traffic_tree = subtree:add(continued_traffic_, buffer(offset))
            pinfo.cols.info = "Continued data"
            subtree:append_text(", Continued data")
            return
        end

        if connection_info.protocol ~= nil and not connection_info.is_obfuscated then
            subtree:append_text(", Non-obfuscated")
        end

        -- handle TCP reassembly, to get the right PDU offset from the beginning of the stream
        local num_bytes_processed = get_pdu_byte_seq_no(pinfo, connection_key, buffer, relative_tcp_offset, is_outgoing)

        local dec_data = buffer(offset)
        local subtree_dec = subtree

        if connection_info.is_obfuscated then
            local obf_enc_key = connection_info.obf_enc_key
            local obf_enc_iv = connection_info.obf_enc_iv
            local obf_dec_key = connection_info.obf_dec_key
            local obf_dec_iv = connection_info.obf_dec_iv
            
            -- assume it's obfuscated
            local obfuscated_traffic_tree = subtree:add(obfuscated_traffic_, buffer(offset))


            --
            -- deofuscate
            --
            
            local decrypted_bytes = nil
            if is_outgoing then
                -- outgoing packet
                decrypted_bytes = deobfuscate(buffer(offset), obf_enc_key, obf_enc_iv, num_bytes_processed, true)
            else
                -- incoming pckaet
                decrypted_bytes = deobfuscate(buffer(offset), obf_dec_key, obf_dec_iv, num_bytes_processed, false)
            end

            --
            -- dissect the deobfuscated frames
            --

            dec_data = ByteArray.new(decrypted_bytes, true):tvb("Deobfuscated MTProto data")
            subtree_dec = subtree:add(dec_data(), "Deobfuscated data")

        end
        
        local info = ""; local frames_count = 0
        offset, frames_count, info = dissect_mtproto_frames(pinfo, subtree_dec, connection_info, dec_data, offset, num_bytes_processed, is_outgoing)

        append_pinfo_string(pinfo, info)

        if connection_info.protocol == "abridged" and connection_info.is_obfuscated then
            subtree:append_text(", Obfuscated, " .. tostring(frames_count) .. " abridged frame(s)")
        elseif connection_info.protocol == "abridged" then
            subtree:append_text(", " .. tostring(frames_count) .. " abridged frame(s)")
        elseif connection_info.protocol == "intermediate" then
            subtree:append_text(", " .. tostring(frames_count) .. " intermediate frame(s)")
        elseif connection_info.protocol == "full" then
            subtree:append_text(", " .. tostring(frames_count) .. " full transport frame(s)")
        end
   
    else
        print("warning: not first packet but no info for connection")
    end
end

function dissect_mtproto_frames(pinfo, subtree, connection_info, buffer, offset, start_tcp_seq, is_outgoing)
    local packets_array_key = is_outgoing and "out_packets" or "in_packets"

    local packet_info = connection_info[packets_array_key][get_packet_key()]

    -- performance: return cached result without full dissection if it's not needed
    if subtree.visible == false and packet_info.cached_info then
        return packet_info.cached_info[1], packet_info.cached_info[2], packet_info.cached_info[3]
    end

    local info = ""
    local frames_count = 0
    local is_parsing_complete = true

    while offset < buffer:len() do
        local prev_offset = offset
        local frame_info = ""
        local is_frame_parsing_complete = false

        local tcp_reassembled_pdu_start_seq_num_key = is_outgoing and "outgoing_tcp_reassembled_pdu_start_seq_num" or "incoming_tcp_reassembled_pdu_start_seq_num"

        offset, is_frame_parsing_complete, frame_info = dissect_mtproto_frame(pinfo, buffer, offset, subtree, connection_info.protocol, is_outgoing)
        
        if is_frame_parsing_complete == false then
            is_parsing_complete = false
        end

        if pinfo.desegment_len > 0 and not packet_info.is_starting_reassembly then
            -- for reassembly: update the number of bytes we read in the connection stream

            packet_info.is_starting_reassembly = true
            packet_info.reassembly_start_tcp_offset = start_tcp_seq + offset
            connection_info[tcp_reassembled_pdu_start_seq_num_key] = packet_info.reassembly_start_tcp_offset
        end

        info = append_to_string(info, frame_info)

        if pinfo.desegment_len ~= 0 then
            -- TCP reassembly; need more bytes
            print("starting reassembly in packet " .. tostring(pinfo.number) .. " from tcp offset: " .. packet_info.reassembly_start_tcp_offset)
            break
        end
        if offset - prev_offset == 0 then
            print("packet number " .. tostring(pinfo.number) .. " looks unsupported")
            break
        end

        frames_count = frames_count + 1
    end

    if is_parsing_complete and info ~= "" and not string.find(info, "%.%.%.") then
        packet_info.cached_info = {offset, frames_count, info}
    end

    return offset, frames_count, info
end

local total_msg_read_time = 0

function dissect_mtproto_frame(pinfo, buffer, offset, tree, protocol, is_outgoing)

    local header_fields_size = 0
    local payload_length = buffer(offset):len()
    local pdu_start_offset = offset
    local frame_info = ""
    local is_parsing_complete = false

    if protocol == "abridged" then
        -- Abridged protocol

        offset, payload_length, header_fields_size = read_abridged_frame_header(pinfo, buffer, offset, tree, is_outgoing)
        if pinfo.desegment_len ~= 0 then
            -- more bytes needed
            return offset, is_parsing_complete, frame_info
        end
        if buffer(offset):len() == 0 then
            -- it was probably a quickack
            return offset, is_parsing_complete, frame_info
        end

    elseif protocol == "intermediate" then
        -- Intermediate protocol

        offset, payload_length, header_fields_size = read_intermediate_frame_header(pinfo, buffer, offset, tree, is_outgoing)
       if pinfo.desegment_len ~= 0 then
           -- more bytes needed
           return offset, is_parsing_complete, frame_info
       end
       if buffer(offset):len() == 0 then
           -- it was probably a quickack
           return offset, is_parsing_complete, frame_info
       end
    elseif protocol == "http" then
        -- HTTP has the Content-Length already encoded in the headers, no need to read it
    elseif protocol == "full" then
        -- Full transport protocol

        offset, payload_length, header_fields_size = read_full_frame_header(pinfo, buffer, offset, tree, is_outgoing)
        if pinfo.desegment_len ~= 0 then
            -- more bytes needed
            return offset, is_parsing_complete, frame_info
        end
    
    else
        return offset, is_parsing_complete, frame_info
        -- TODO: support other protocols
    end


    local pdu_end_offset = pdu_start_offset + header_fields_size + payload_length

    -- performance boost: try to avoid deep dissection when not needed
    -- TODO: maybe we can do a better performance boost
    -- bug: but the request-response mapping won't be updated for the current packet unless you re-enter it  
    if pinfo.visited == false then
        return pdu_end_offset, false, "..."
    end

    --
    -- now read the actual payload, regardless of the transport type
    --

    local frame_tree = tree:add(mtproto_payload_, buffer(offset, payload_length)):set_text("MTProto Frame")

    if payload_length == 4 then
        -- Transport Error
        -- https://core.telegram.org/mtproto/mtproto-transports#transport-errors
        local error_code = buffer(offset, 4):le_int()
        frame_tree:add_le(frame_error_code_, buffer(offset, 4)); offset = offset + 4
        append_pinfo_string(pinfo, "Error code: " .. tostring(error_code))

        -- TODO: use the errors JSON information from telegram website

        return offset, is_parsing_complete, frame_info
    end

    local frame_start_offset = offset
    
    local auth_key_id_number = buffer(offset, 8):uint64()
    local auth_key_id_tree = frame_tree:add(auth_key_id_, buffer(offset, 8)); offset = offset + 8

    local is_encrypted_message = auth_key_id_number:tonumber() ~= 0
    if is_encrypted_message then
        -- read the encryption header and payload
        local msg_key_ba = buffer(offset, 16):bytes()
        frame_tree:add(msg_key_, buffer(offset, 16)); offset = offset + 16

        local encrypted_message_length = payload_length - 24 -- minus auth_key_id and msg_key
        local encrypted_message_buffer = buffer(offset, encrypted_message_length)
        local message_tree = frame_tree:add(encrypted_message_, encrypted_message_buffer)

        -- try to decrypt it
        -- (the TvbRange:raw() code is a workaround for a bug in Wireshark ~v3.2: https://gitlab.com/wireshark/wireshark/-/issues/17034)
        local encrypted_message_string = buffer:raw(offset):sub(0, encrypted_message_length)

        local decrypted_bytes = decrypt_message(encrypted_message_string, auth_key_id_number, msg_key_ba, is_outgoing)
        if decrypted_bytes then

            local dec_buffer = ByteArray.new(decrypted_bytes, true):tvb("Decrypted MTProto message")
            local subtree_dec = frame_tree:add(decrypted_message_, dec_buffer()):set_text("Decrypted message")
            local decrypted_data_length = dec_buffer:len()

            -- dissect decrypted header and fields

            local offset_dec = 0
            subtree_dec:add(salt_, dec_buffer(offset_dec, 8)); offset_dec = offset_dec + 8
            subtree_dec:add(session_id_, dec_buffer(offset_dec, 8)); offset_dec = offset_dec + 8
            local inner_message_size, is_msg_parsing_complete, msg_info = read_decrypted_message_inner(pinfo, subtree_dec, dec_buffer, offset_dec, is_outgoing)
            offset_dec = offset_dec + inner_message_size; offset = offset + inner_message_size
            frame_info = msg_info; is_parsing_complete = is_msg_parsing_complete

            local size_read = offset_dec
            local padding_length = decrypted_data_length - size_read
            if padding_length > 0 then
                subtree_dec:add(frame_padding_, dec_buffer(offset_dec, padding_length)):set_text("Padding (random bytes)")
                offset = offset + padding_length
            end

        else
            -- can't decrypt
            frame_info = "Encrypted message"
            offset = offset + encrypted_message_length
        end

    else
        -- not encrypted

        auth_key_id_tree:append_text(" (unencrypted message)");
        offset = read_msg_id_field(pinfo, frame_tree, buffer, offset)
        local mtproto_message_size, is_msg_parsing_complete, msg_info = dissect_mtproto_message(pinfo, frame_tree, buffer, offset, is_outgoing)
        offset = offset + mtproto_message_size
        frame_info = msg_info
        is_parsing_complete = is_msg_parsing_complete

        local size_read = offset - frame_start_offset
        local frame_padding_length = payload_length - size_read
        if frame_padding_length > 0 then
            frame_tree:add(frame_padding_, buffer(offset, frame_padding_length)):set_text("Padding (random bytes)")
            offset = offset + frame_padding_length
        end

    end

    if protocol == "full" then
        local computed_crc32 = crc32(buffer(pdu_start_offset, offset - pdu_start_offset))
        local read_crc32 = buffer(offset, 4):le_uint()
        local crc32_tree = tree:add_le(crc32_, buffer(offset, 4)); offset = offset + 4
        if read_crc32 == computed_crc32 then
            crc32_tree:append_text(" [correct]")
        end
    end

    frame_tree:append_text(" [" .. frame_info .. "]")

    offset = pdu_end_offset -- assume we read everything

    return offset, is_parsing_complete, frame_info

end

function read_decrypted_message_inner(pinfo, subtree_dec, dec_data, offset)
    local initial_offset = offset

    offset = read_msg_id_field(pinfo, subtree_dec, dec_data, offset)
    local seq_no_tree = subtree_dec:add_le(seq_no_, dec_data(offset, 4)); 
    local seq_no_full_value = dec_data(offset, 4):le_uint()
    local seq_no_value = bit.rshift(bit.band(seq_no_full_value, 0xFFFFFFFE), 1)
    seq_no_tree:add_le(seq_no_value_, dec_data(offset, 4)); 
    seq_no_tree:add_le(flag_contentmsg_, dec_data(offset, 4))
    seq_no_tree:set_text("Sequence Number: " .. tostring(seq_no_value) .. "  (" .. string.format("0x%08X", seq_no_full_value) .. ")")
    offset = offset + 4


    local total_msg_length, is_parsing_complete, info = dissect_mtproto_message(pinfo, subtree_dec, dec_data, offset)
    offset = offset + total_msg_length

    local inner_msg_size = offset - initial_offset
    return inner_msg_size, is_parsing_complete, info
end

function read_abridged_frame_header(pinfo, buffer, offset, tree, is_outgoing)
    local length_fields_size = 0

    local pdu_start_offset = offset

    local is_extended_length = false
    local is_quickack_request = false

    -- is it quick-ack response by chance? (not common)
    if not is_outgoing and buffer(offset):len() == 4 then
        local quickack_token_be = buffer(offset, 4):uint()
        if bit.band(quickack_token_be, 0x80000000) ~= 0 then
            -- yes, it's quick ack response
            tree:add_le(quickac_token_, buffer(offset, 4)); offset = offset + 4
            append_pinfo_string(pinfo, "Quick-Ack")
            return offset, 4, length_fields_size
        end
    end

    -- regular frame.
    -- read lengths fields and check if it it makes sense

    local payload_length = buffer(offset, 1):uint() * 4

    -- is it quick-ack request? (not common)
    if is_outgoing and payload_length / 4 > 0x7f and payload_length / 4 <= 0xff then
        -- we have quick-ack request
        payload_length = payload_length - (128 * 4)
        is_quickack_request = true
    end
    

    -- read extended length header if needed
    length_fields_size = 1
    if payload_length / 4 == 0x7f or payload_length / 4 == 0xff then
        is_extended_length = true
        length_fields_size = 4

        if buffer(pdu_start_offset):len() < length_fields_size then
            print("rare case: not enough bytes to read extended header, requesting a few more bytes")
            pinfo.desegment_len = length_fields_size - buffer(pdu_start_offset):len()
            pinfo.desegment_offset = pdu_start_offset

            print("buffer:len() == " .. buffer:len() .. ", pdu_start_offset == " .. pdu_start_offset)
            next_expected_pdu_length = length_fields_size
            return offset, payload_length, length_fields_size
        end

        local payload_length_extended = buffer(offset + 1, 3):le_uint() * 4
        payload_length = payload_length_extended
    end

    local payload_start = offset + length_fields_size
    print("payload_length = " .. payload_length .. ", buffer(payload_start):len() = " .. buffer(payload_start):len())

    -- request more TCP fragments if needed

    if payload_length > buffer(payload_start):len() then
        -- we don't have enough bytes in this packet, so we need to reassembly
        print("packet " .. pinfo.number .. ": requesting more TCP data")

        local expected_pdu_length = length_fields_size + payload_length
        pinfo.desegment_offset = pdu_start_offset
        pinfo.desegment_len = (expected_pdu_length) - buffer(pdu_start_offset):len() -- number of missing bytes
        print("pdu_start_offset is " .. pdu_start_offset)
        print("expected_pdu_length = " .. expected_pdu_length)
        print("pinfo.desegment_len = " .. pinfo.desegment_len)  

        -- NOTE: logs here may not appear if we don't create a new tree or something
        -- NOTE: to debug reassembly bugs, add to the upper if statement: "and pinfo.number < your_buggy_packet_number"

        next_expected_pdu_length = expected_pdu_length
        return offset, payload_length, length_fields_size
    else
        -- we have enough bytes, good
        next_expected_pdu_length = 0
    end

    -- add up the lengths fields to the tree

    local length_tree = tree:add_le(length_, buffer(offset, 1)); offset = offset + 1
    length_tree:add(flag_quickackreq,          buffer(offset - 1, 1))

    if not is_extended_length then
        length_tree:set_text("MTProto Frame Length: " .. tostring(payload_length) .. " (" .. payload_length / 4 .. ")")
    else
        -- read the extended length
        length_tree:set_text("MTProto Frame Length: 0xff [MAX]")
        local lengthext_tree = tree:add_le(length_ext_, buffer(offset, 3)); offset = offset + 3
        lengthext_tree:set_text("MTProto Frame Length (extended): " .. tostring(payload_length) .. " (" .. payload_length / 4 .. ")")
    end

    return offset, payload_length, length_fields_size
end

function read_intermediate_frame_header(pinfo, buffer, offset, tree, is_outgoing)
    local length_fields_size = 0

    local pdu_start_offset = offset

    local is_extended_length = false
    local is_quickack_request = false

    -- is it quick-ack response by chance? (not common)
    if not is_outgoing and buffer(offset):len() == 4 then
        local quickack_token_be = buffer(offset, 4):uint()
        if bit.band(quickack_token_be, 0x80000000) ~= 0 then
            -- yes, it's quick ack response
            tree:add_le(quickac_token_, buffer(offset, 4)); offset = offset + 4
            append_pinfo_string(pinfo, "Quick-Ack")
            return offset, 4, length_fields_size
        end
    end

    -- regular frame.
    -- read lengths fields and check if it it makes sense

    length_fields_size = 4
    local header_fields_size = length_fields_size

    if buffer(pdu_start_offset):len() < length_fields_size then
        print("rare case: not enough bytes to read intermediate transport header, requesting a few more bytes")
        pinfo.desegment_len = header_fields_size - buffer(pdu_start_offset):len()
        pinfo.desegment_offset = pdu_start_offset

        print("buffer:len() == " .. buffer:len() .. ", pdu_start_offset == " .. pdu_start_offset)
        next_expected_pdu_length = header_fields_size
        return offset, 0xff, header_fields_size
    end

    local payload_length = buffer(offset, 4):le_uint()

    -- is it quick-ack request? (not common)
    if is_outgoing and payload_length > 0x80000000 then
        -- we have quick-ack request
        payload_length = payload_length - 0x80000000
        is_quickack_request = true
    end
    

    local payload_start_offset = offset + length_fields_size
    print("payload_length = " .. payload_length .. ", buffer(payload_start):len() = " .. buffer(payload_start_offset):len())

    -- request more TCP fragments if needed

    if payload_length > buffer(payload_start_offset):len() then
        -- we don't have enough bytes in this packet, so we need to reassembly
        print("packet " .. pinfo.number .. ": requesting more TCP data")

        local expected_pdu_length = header_fields_size + payload_length
        pinfo.desegment_offset = pdu_start_offset
        pinfo.desegment_len = (expected_pdu_length) - buffer(pdu_start_offset):len() -- number of missing bytes
        print("pdu_start_offset is " .. pdu_start_offset)
        print("expected_pdu_length = " .. expected_pdu_length)
        print("pinfo.desegment_len = " .. pinfo.desegment_len)  

        -- NOTE: logs here may not appear if we don't create a new tree or something
        -- NOTE: to debug reassembly bugs, add to the upper if statement: "and pinfo.number < your_buggy_packet_number"

        next_expected_pdu_length = expected_pdu_length
        return offset, payload_length, header_fields_size
    else
        -- we have enough bytes, good
        next_expected_pdu_length = 0
    end

    -- add up the lengths fields to the tree

    local length_tree = tree:add_le(intermediate_length_, buffer(offset, 4)); offset = offset + 4
    length_tree:add(flag_quickackreq,          buffer(offset - 4, 1))

    if not is_extended_length then
        length_tree:set_text("MTProto Frame Length: " .. tostring(payload_length))
    end

    return offset, payload_length, header_fields_size
end

function read_full_frame_header(pinfo, buffer, offset, tree, is_outgoing)
    -- https://core.telegram.org/mtproto/mtproto-transports#full
    
    local length_fields_size = 0

    local pdu_start_offset = offset

    -- regular frame.
    -- read lengths fields and check if it it makes sense

    local frame_length = buffer(offset, 4):le_uint()
    length_fields_size = 4
    local header_fields_length = length_fields_size + 4 + 4 -- plus seqno plus crc32 == 12

    if buffer(pdu_start_offset):len() < length_fields_size then
        print("rare case: not enough bytes to read extended header, requesting a few more bytes")
        pinfo.desegment_len = length_fields_size - buffer(pdu_start_offset):len()
        pinfo.desegment_offset = pdu_start_offset

        print("buffer:len() == " .. buffer:len() .. ", pdu_start_offset == " .. pdu_start_offset)
        next_expected_pdu_length = length_fields_size
        return offset, frame_length - 12, length_fields_size
    end

    local payload_start = offset + length_fields_size
    print("frame_length = " .. frame_length .. ", buffer(payload_start):len() = " .. buffer(payload_start):len())

    -- request more TCP fragments if needed

    if frame_length > buffer(pdu_start_offset):len() then
        -- we don't have enough bytes in this packet, so we need to reassembly
        print("packet " .. pinfo.number .. ": requesting more TCP data")

        local expected_pdu_length = frame_length
        pinfo.desegment_offset = pdu_start_offset
        pinfo.desegment_len = (expected_pdu_length) - buffer(pdu_start_offset):len() -- number of missing bytes
        print("pdu_start_offset is " .. pdu_start_offset)
        print("expected_pdu_length = " .. expected_pdu_length)
        print("pinfo.desegment_len = " .. pinfo.desegment_len)  

        -- NOTE: logs here may not appear if we don't create a new tree or something
        -- NOTE: to debug reassembly bugs, add to the upper if statement: "and pinfo.number <= your_buggy_packet_number"

        next_expected_pdu_length = expected_pdu_length
        return offset, frame_length - header_fields_length, header_fields_length
    else
        -- we have enough bytes, good
        next_expected_pdu_length = 0
    end

    -- add up the lengths fields to the tree

    local length_tree = tree:add_le(full_length_, buffer(offset, 4)); offset = offset + 4
    tree:add_le(full_seqno_, buffer(offset, 4)); offset = offset + 4

    local payload_length = frame_length - header_fields_length -- minus length, seqno, crc32 fields

    return offset, payload_length, header_fields_length
end

function get_pdu_byte_seq_no(pinfo, connection_key, buffer, relative_tcp_offset, is_outgoing)
    --local num_bytes_processed = tcp_seq_num()() - 1
    local connection_info = connection_infos[connection_key]
    local first_tcp_seq_num_key = is_outgoing and "out_first_tcp_seq_num" or "in_first_tcp_seq_num"
    local first_tcp_seq_num = connection_info[first_tcp_seq_num_key]

    local packets_array_key = is_outgoing and "out_packets" or "in_packets"
    local packet_key = get_packet_key()
    local packet_info = connection_info[packets_array_key][packet_key]
    
    local num_bytes_processed = tcp_seq_num_raw()() - first_tcp_seq_num

    print("buffer:len() = " .. buffer:len() .. ", next_expected_pdu_length = " .. next_expected_pdu_length)
    -- If this is a PDU composed of multiple TCP segments, take the memorized TCP sequence number at which the PDU starts
    -- TODO: there could be a bug if the condition is true by chance, it's not the most correct way to detect this
    local is_reassembled_pdu = buffer:len() > tcp_len()() or buffer:len() == next_expected_pdu_length or relative_tcp_offset < 0 
    if is_reassembled_pdu then
        
        -- This buffer was reassembled from multiple TCP segments
        -- get the PDU seq num and cache it

        num_bytes_processed = packet_info.num_bytes_processed

        local was_in_cache = true
        if num_bytes_processed == nil then
            -- not in cache of packet, get from connection
            was_in_cache = false
            local tcp_reassembled_pdu_start_seq_num_key = is_outgoing and "outgoing_tcp_reassembled_pdu_start_seq_num" or "incoming_tcp_reassembled_pdu_start_seq_num"
            num_bytes_processed = connection_info[tcp_reassembled_pdu_start_seq_num_key]

            -- insert to packet cache
            packet_info.num_bytes_processed = num_bytes_processed 
        end

        packet_info.is_reassembled_packet = true

        print("packet " .. tostring(pinfo.number) .. " is reassembled from TCP offset " .. tostring(num_bytes_processed) .. " (from cache: " .. tostring(was_in_cache) .. ")")
    else
        print("Offset into TCP payload: " .. relative_tcp_offset)
        num_bytes_processed = num_bytes_processed + relative_tcp_offset
    end

    print("num_bytes_processed for packet " .. pinfo.number .. " is " .. num_bytes_processed)

    return num_bytes_processed
end

function dissect_mtproto_message(pinfo, mtproto_tree, buffer, offset)
    local initial_offset = offset
    local message_length = buffer(offset, 4):le_uint()

    mtproto_tree:add_le(message_length_, buffer(offset, 4)):append_text(""); offset = offset + 4

    local message_start_offset = offset
    local message_tree = mtproto_tree:add(plain_message_, buffer(offset, message_length)):set_text("MTProto TL Message")
    
    local read_msg_size, info, is_parsing_complete = dissect_tl_message_payload(pinfo, message_tree, buffer, offset)
    offset = offset + read_msg_size

    if is_parsing_complete then
        local padding_length = message_length - read_msg_size
        local read_size = (offset - message_start_offset)
        if padding_length > 0 then
            -- seems like the rest should be padding
            message_tree:add(inner_padding_, buffer(offset, padding_length)):set_text("Inner Padding (random size, random bytes)") ; offset = offset + padding_length
        end
    end

    offset = message_start_offset + message_length

    local total_message_length = offset - initial_offset
    return total_message_length, is_parsing_complete, info
    
end

--
-- TL dissection
-- 

function dissect_tl_message_payload(pinfo, message_tree, buffer, offset)
    local message_start_offset = offset
    local is_parsing_complete = false
    local found_type_name = nil
    local info = ""
    
    local message_type = buffer(offset, 4):le_uint()
    local message_type_tree = message_tree:add_le(message_type_, buffer(offset, 4)); offset = offset + 4

    -- is it by chance a service message?
    local is_service_msg, service_msg_name = is_special_type_tl_msg(message_type)
    if is_service_msg then
        message_type_tree:append_text(" [" .. service_msg_name .. "]")
        found_type_name = service_msg_name

        offset, is_parsing_complete, info = read_tl_special_type_msg(pinfo, message_tree, buffer, offset, service_msg_name)

    else
        --
        -- find the params for the message type
        --

        local found_type_info = nil
        found_type_name, found_type_info = get_tl_type_info(message_type)

        if found_type_info then
            -- good
            message_type_tree:append_text(" [" .. found_type_name .. "]")

            offset, is_parsing_complete, info = read_fields_of_complex_tl_type(pinfo, message_tree, buffer, offset, found_type_info)
            
            if info == "" then
                info = found_type_name
            else
                info = found_type_name .. "(" .. info ..")"
            end
        else
            info = "?"
            message_type_tree:append_text(" [UNKNOWN]")
            message_tree:add_proto_expert_info(expert_info_incomplete_parsing)
        end
    end

    local read_size = (offset - message_start_offset)

    return read_size, info, is_parsing_complete
end


function read_tl_type(pinfo, message_tree, buffer, offset)
    local message_start_offset = offset
    local is_parsing_complete = false
    local found_type_name = nil
    local info = ""
    
    local type_constructor_number = buffer(offset, 4):le_uint()
    local type_tree_label = "Type Constructor: " .. string.format("0x%04x", type_constructor_number)
    local type_name_tree = message_tree:add_le(complex_type_constructor_, buffer(offset, 4)):set_text(type_tree_label); offset = offset + 4
   
    --
    -- find the params for the constructor
    --

    local found_type_info = nil
    found_type_name, found_type_info = get_tl_type_info(type_constructor_number)

    if found_type_info then
        -- good
        type_name_tree:append_text(" [" .. found_type_name .. "]")

        offset, is_parsing_complete, info = read_fields_of_complex_tl_type(pinfo, message_tree, buffer, offset, found_type_info)
        
        if info == "" then
            info = found_type_name
        else
            info = found_type_name .. "(" .. info .. ")"
        end
    else
        info = "?"
        type_name_tree:append_text(" [UNKNOWN]")
        message_tree:add_proto_expert_info(expert_info_incomplete_parsing)
    end

    local read_size = (offset - message_start_offset)

    return read_size, info, is_parsing_complete
end

function read_fields_of_complex_tl_type(pinfo, message_tree, buffer, offset, type_info)
    local is_parsing_complete_all = true
    local hash_sign_fields = {}
    local info = ""

    for i, param_info in ipairs(type_info["params"]) do
        local param_name = param_info["name"]
        local param_type = param_info["type"]
        local should_include = true
        local is_conditional_field = false
        local is_bool_conditional_field = false

        -- print("param " .. i .. ": " .. param_info["name"] .. " which is " .. param_info["type"])

        --
        -- take care of special fields
        --

        if param_type:find("?") then
             -- we have a conditional field like "flags.0?InputClientProxy"
             -- https://core.telegram.org/mtproto/TL-combinators#conditional-fields
             is_conditional_field = true

            -- we need to check if this field should be included
            local parts_q = split(param_type, "?")
            local field_and_bitnumber = parts_q[1] 
            local inner_param_type = parts_q[2]

            local parts_dot = split(field_and_bitnumber, ".")
            local hash_field_name_to_check = parts_dot[1]
            local bit_number_str = parts_dot[2]

            local flags_field_value = hash_sign_fields[hash_field_name_to_check][1]
            local flags_field_tree = hash_sign_fields[hash_field_name_to_check][2]
            local flags_field_offset = hash_sign_fields[hash_field_name_to_check][3]

            if inner_param_type == "true" then
                is_bool_conditional_field = true
            end
            
            if bit_number_str ~= "" then
                if flags_field_value then
                    local bit_number = tonumber(bit_number_str)
                    should_include = bit.band(flags_field_value, bit.lshift(1, bit_number)) ~= 0    
                else
                    -- TODO: maybe expert info
                    message_tree:append_text(" [ERROR: couldn't find field '" .. tostring(hash_field_name_to_check) .. "']")
                end

            else
                -- by TL specs, no bit number means check the whole 32 bit number
                should_include = flags_field_value ~= 0
            end

            local bit_number = tonumber(bit_number_str)
            -- can we put real bitfield?
            -- local flag_tree = ProtoField.bool("mtproto.flag", "Flag " .. param_name, 32, {"true", "false"}, bit.lshift(1, bit_number))
            local value_string = ""
            if is_bool_conditional_field then
                value_string = "false"
                if should_include then
                    value_string = "true"
                end
            else
                value_string = "not included"
                if should_include then
                    value_string = "INCLUDED"
                end
            end

            flags_field_tree:add(buffer(flags_field_offset, 4), "Bool " .. param_type .. " " .. param_name .. ": " .. value_string)

            if should_include then
                param_type = inner_param_type
            end

        end


        if not is_bool_conditional_field and should_include then
            -- regular field

            local field_text = param_type .. " " .. param_name

            ---
            --- read the field contents
            ---

            local field_tree, type_size, is_parsing_complete, field_info = read_tl_field(pinfo, message_tree, buffer, offset, field_text, param_type, param_name)

            if field_info ~= "" then
                -- it's probably an important info
                info = append_to_string(info, field_info)
            end

            if param_type == "#" then
                -- this was a flags field, remember it
    
                local field_value = buffer(offset, 4):le_int()
                hash_sign_fields[param_name] = {field_value, field_tree, offset}
            end

            if not is_parsing_complete then
                is_parsing_complete_all = is_parsing_complete
                message_tree:add_proto_expert_info(expert_info_incomplete_parsing)
                break
            end

            offset = offset + type_size  

            if offset == buffer:len() then
                break
            end
        end

    end

    return offset, is_parsing_complete_all, info
end

function read_tl_field(pinfo, msg_tree, buffer, offset, field_text, param_type, param_name)
    local is_parsing_complete = true
    local type_size = 0
    local info = ""

    -- try to see if it is a known boxed constructor
    local possible_constructor_number = buffer(offset, 4):le_uint()
    local found_type_name, type_info = get_tl_type_info(possible_constructor_number)

    local field_tree = nil
    if param_type == "string" or param_type == "bytes" then
        field_tree = msg_tree:add(bytes_tl_field_, buffer(offset, 0)):set_text(field_text)
    elseif param_type:find("^Vector<") then
        field_tree = msg_tree:add(vector_tl_field_, buffer(offset, 0)):set_text(field_text)
    elseif type_info ~= nil then
        field_tree = msg_tree:add(complex_tl_field_, buffer(offset, 0)):set_text(field_text)
    elseif param_type == "#" then
        field_tree = msg_tree:add(flags_tl_field_, buffer(offset, 4)):set_text(field_text)
    else
        field_tree = msg_tree:add(tl_field_, buffer(offset, 0)):set_text(field_text)
    end

    -- https://core.telegram.org/mtproto/serialize

    if param_type == "int" then
        -- https://core.telegram.org/type/int
        type_size = 4
        field_tree:append_text(": " .. tostring(buffer(offset, type_size):le_uint()))
    elseif param_type == "long" then
        -- https://core.telegram.org/type/long
        type_size = 8
        local long_string = "0x" .. buffer(offset, type_size):le_uint64():tohex()

        if looks_like_decimal_id_param(param_name) then
            -- special case: these fields probably should be shown as decimals
            long_string = buffer(offset, type_size):le_uint64()
        end
        field_tree:append_text(": " .. long_string)
    elseif param_type == "double" then
        -- https://core.telegram.org/type/double
        type_size = 8
        field_tree:append_text(": " .. tostring(buffer(offset, type_size)))
    elseif param_type == "int128" then
        type_size = 16
        field_tree:append_text(": " .. tostring(buffer(offset, type_size)))
    elseif param_type == "true" or param_type == "false" then
        type_size = 0
        field_tree:append_text(": " .. param_type)
    elseif param_type == "string" or param_type == "bytes" then
        local string_size, string_tvb = read_tl_string_or_bytes_contents(field_tree, buffer, offset)
        local string_value = tostring(string_tvb)
        local raw_string = ByteArray.new(string_value):raw()
        if is_all_ascii(raw_string) then
            string_value = '"' .. raw_string .. '"'
        end

        type_size = string_size

        field_tree:append_text(": " .. string_value)
    elseif param_type:find("^Vector<") then
        local vector_value = "<>"
        
        type_size, is_parsing_complete = read_tl_vector_contents(pinfo, field_tree, buffer, offset, param_type, param_name)
    elseif param_type == "#" then
        -- https://core.telegram.org/type/%23, https://core.telegram.org/mtproto/TL-combinators#conditional-fields
        type_size = 4
        field_tree:append_text(": 0x" .. string.format("%x", buffer(offset, type_size):le_uint()))
        
    elseif param_type == "!X" then
        local read_size, x_info, is_type_parsing_complete_inner = read_tl_type(pinfo, field_tree, buffer, offset)
        field_tree:append_text(" [" .. x_info .. "]")
        info = x_info

        type_size = read_size
        is_parsing_complete = is_type_parsing_complete_inner
    else
        -- probably complex type
        if type_info then
            local read_size, info, is_type_parsing_complete_inner = read_tl_type(pinfo, field_tree, buffer, offset)

            type_size = read_size
            is_parsing_complete = is_type_parsing_complete_inner
        else
            is_parsing_complete = false
            print("encountered unknown type: " .. param_type)
            field_tree:append_text(" [UNKNOWN TYPE]")
        end

    end

    field_tree:set_len(type_size)
    offset = offset + type_size
        

    return field_tree, type_size, is_parsing_complete, info
end

function read_tl_string_or_bytes_contents(message_tree, buffer, offset)
    -- https://core.telegram.org/type/string, https://core.telegram.org/type/bytes
    -- https://core.telegram.org/mtproto/serialize
    -- Telegram says that "All strings passed to the API must be encoded in UTF-8", but in practice q and p in resPQ are encoded with string

    local initial_offset = offset

    local initial_length_value = buffer(offset, 1):uint()
    local length_value = initial_length_value
    local size_of_length_field = 1

    if initial_length_value <= 253 then
        message_tree:add(buffer(offset, 1), "Length: " .. tostring(initial_length_value)); offset = offset + 1
    else
        -- long length version
        message_tree:add(buffer(offset, 1), "Length: " .. tostring(initial_length_value) .. " [MAX]"); offset = offset + 1
        local length_extended = buffer(offset, 3):le_uint()
        message_tree:add(buffer(offset, 3), "Length (extended): " .. tostring(length_extended)); offset = offset + 3
        length_value = length_extended
        size_of_length_field = 4
    end

    local string_tvb = buffer(offset, length_value)
    local string_value = tostring(string_tvb)
    local raw_string = ByteArray.new(string_value):raw()
    if is_all_ascii(raw_string) then
        string_value = '"' .. raw_string .. '"'
    end

    message_tree:add(buffer(offset, length_value), "Value: " .. string_value); offset = offset + length_value
    local length_mod_4 = (size_of_length_field + length_value) % 4
    if (length_mod_4 > 0) then
        local padding_length = 4 - length_mod_4
        local padding_value = buffer(offset, padding_length)
        message_tree:add(padding_value, "Padding (to multiples of 4): " .. tostring(padding_value)); offset = offset + padding_length
    end

    local type_size = offset - initial_offset

    return type_size, string_tvb
end

function read_tl_vector_contents(pinfo, vector_tree, buffer, offset, type_name, vector_name)
    -- performance boost: don't add large vectors to the tree, unless the user is actually viewing the packet
    if buffer(offset):len() > 10000 and vector_tree.visible == false then
        return 0, false
    end


    -- type_name should be for example "Vector<long>"
    local element_type = type_name:match("^Vector<([^>]+)>$")
    local is_generic_vector = type_name == "vector"
    local is_boxed = not is_generic_vector

    local initial_offset = offset

    if is_boxed then
        vector_tree:add(buffer(offset, 4), "Vector constructor constant: " .. tostring(buffer(offset, 4))); offset = offset + 4 -- TODO: check it's 15c4b51c
    end
    
    local elements_count = buffer(offset, 4):le_uint()
    vector_tree:add(buffer(offset, 4), "Elements Count: " .. tostring(elements_count)); offset = offset + 4

    local is_parsing_complete_all = true

    for i=1, elements_count do
        if is_generic_vector then
            -- peek forward to get the element type
            local possible_constructor_number = buffer(offset, 4):le_uint()
            local found_type_name, found_type_info = get_tl_type_info(possible_constructor_number)
            element_type = found_type_name
        end

        if element_type == nil then
            element_type = "UNKNOWN"
        end

        local element_text = "Element #" .. tostring(i) .. " (" .. element_type .. ")"
        if vector_name == "msg_ids" then
            element_text = "Message ID #" .. tostring(i) .. " (" .. element_type .. ")"
        end
        local element_tree, type_size, is_parsing_complete, info = read_tl_field(pinfo, vector_tree, buffer, offset, element_text, element_type, tostring(i))

        if vector_name == "msg_ids" then
            -- this is probably msgs_ack list
            local msg_id = buffer(offset, 8):uint64():tonumber()
            msg_ids_to_ack_packet_numbers[msg_id] = pinfo.number

            local msg_frame_num = msg_ids_to_packet_numbers[msg_id]
            if msg_frame_num then
                element_tree:add(msg_in_frame_, msg_frame_num):set_generated(true)
            end
        end
        
        offset = offset + type_size

        if not is_parsing_complete then
            is_parsing_complete_all = false
            vector_tree:add_proto_expert_info(expert_info_incomplete_parsing)
            break
        end
    end

    local vector_total_size = offset - initial_offset
    return vector_total_size, is_parsing_complete_all
    
end


function prepare_tl_type_map()
    -- search for both api.tl and mtproto.tl for types\methods information
    -- index by type id

    local found_method_info = nil
    local found_type_name = nil

    -- is it method?
    for i, method_info in ipairs(mtproto_schema["methods"]) do
        local method_id = method_info["id"]
        tl_type_map[method_id] = method_info
    end
    for i, method_info in ipairs(api_schema["methods"]) do
        local method_id = method_info["id"]
        tl_type_map[method_id] = method_info
    end

    -- is it type constructor?
    -- try to search in one of the types, for example in a server response
    for i, method_info in ipairs(mtproto_schema["constructors"]) do
        local method_id = method_info["id"]
        if method_id then
            tl_type_map[method_id] = method_info
        end
    end
    for i, method_info in ipairs(api_schema["constructors"]) do
        local method_id = method_info["id"]
        if method_id then
            tl_type_map[method_id] = method_info
        end
    end
end

function load_tl_schema_for_layer(layer)
    local schema_filename = script_path .. "schema\\api_tl_schema_layer_" ..  tostring(layer) .. ".json"
    local api_schema_file = io.open(schema_filename, "rb")
    if api_schema_file == nil then
        error("Can't load API schema: file " .. schema_filename .. " not found!")
    end

    local api_schema_json, err = api_schema_file:read("*all")
    api_schema = json.decode(api_schema_json)
    api_schema_file:close()

    tl_type_map = {}
    prepare_tl_type_map()
end

function telegram_proto.prefs_changed()
    loaded_layer = telegram_proto.prefs.api_layer
    load_tl_schema_for_layer(loaded_layer)
end


function get_tl_type_info(type_id)
    -- search for both api.tl and mtproto.tl for types\methods information
    -- use the cache

    local found_method_info = nil
    local found_type_name = nil

    if tl_type_map[type_id] then
        found_method_info = tl_type_map[type_id]
        if found_method_info["method"] then
            found_type_name = found_method_info["method"]
        elseif found_method_info["predicate"] then
            found_type_name = found_method_info["predicate"]
        end
    end

    return found_type_name, found_method_info
end

function is_special_type_tl_msg(type_id)
    
    -- is it a special/service type?
    -- https://core.telegram.org/mtproto/service_messages
    local special_type_codes = {
        [0x73f1f8dc] = "msg_container",
        [0xe06046b2] = "msg_copy", -- not used
        [0x3072cfa1] = "gzip_packed",
        [0xf35c6d01] = "rpc_result",
        [0x1cb5c415] = "vector",
    }

    local found_type_name = special_type_codes[type_id]

    if found_type_name then
        return true, found_type_name
    end

    return false, nil
end

function read_tl_special_type_msg(pinfo, message_tree, buffer, offset, msg_type_name)
    local initial_offset = offset
    local is_parsing_complete = true
    local info = msg_type_name

    if msg_type_name == "msg_container" then
        -- https://core.telegram.org/mtproto/service_messages#containers
        -- read container (very common) messages

        local container_info = ""

        local messages_count = buffer(offset, 4):le_uint()
        message_tree:add(buffer(offset, 4), "Messages Count: " .. tostring(messages_count)); offset = offset + 4
        for i=1, messages_count do
            local inner_msg_tree = message_tree:add(inner_message_, buffer(offset, 0)):set_text("Message #" .. tostring(i))

            local inner_msg_size, is_msg_parsing_complete, msg_info = read_decrypted_message_inner(pinfo, inner_msg_tree, buffer, offset)
            inner_msg_tree:append_text(" [" .. msg_info .. "]")

            container_info = append_to_string(container_info, msg_info)
            inner_msg_tree:set_len(inner_msg_size)
            is_parsing_complete = is_msg_parsing_complete
            offset = offset + inner_msg_size

        end

        info = msg_type_name .. ": " .. container_info


    elseif msg_type_name == "rpc_result" then
        -- https://core.telegram.org/mtproto/service_messages#response-to-an-rpc-query

        local req_message_id = buffer(offset, 8):uint64():tonumber()
        message_tree:add_le(rpc_result_req_msg_id_, buffer(offset, 8)); offset = offset + 8
        local req_frame_num = msg_ids_to_packet_numbers[req_message_id]
        if req_frame_num then
            message_tree:add_le(request_in_frame_, req_frame_num):set_generated(true); 
        end
        req_msg_ids_to_res_frame[req_message_id] = pinfo.number

        local rpc_result_tree = message_tree:add(rpc_result_message_, buffer(offset, 0)):set_text("RPC Result Message")
        local read_size, rpc_info, rpc_is_parsing_complete = dissect_tl_message_payload(pinfo, rpc_result_tree, buffer, offset)

        rpc_result_tree:set_len(read_size)

        offset = offset + read_size
        info = msg_type_name .. ": " .. rpc_info
        is_parsing_complete = rpc_is_parsing_complete

    elseif msg_type_name == "gzip_packed" then
        local gzip_packed_tree = message_tree:add(buffer(offset, 0), "Gzip Packed Object")
        local type_size, compressed_gzip_tvb_range = read_tl_string_or_bytes_contents(gzip_packed_tree, buffer, offset)

        gzip_packed_tree:set_len(type_size)

        if compressed_gzip_tvb_range(0,2):uint() == 0x1f8b then
            compressed_gzip_tvb_range = compressed_gzip_tvb_range(10)
            local decompressed_gzip_tvb_range = decompress_gzip(compressed_gzip_tvb_range)
            if decompressed_gzip_tvb_range then
                local unzipped_tree = message_tree:add(decompressed_gzip_tvb_range, "Unzipped Object")
                local read_size, unzip_info, unzip_is_parsing_complete = dissect_tl_message_payload(pinfo, unzipped_tree, decompressed_gzip_tvb_range, 0)

                unzipped_tree:append_text(" [" .. unzip_info .. "]")

                info = unzip_info -- don't include the "gzip_packed" in the info
                is_parsing_complete = unzip_is_parsing_complete
            else
                -- TODO: add expert info unzip failed
            end
        else
            -- TODO: add expert info: bad gzip header
        end

        offset = offset + type_size

        gzip_packed_tree:append_text(": " .. tostring(compressed_gzip_tvb_range))
    elseif msg_type_name == "vector" then
        local vector_value = "<>"
        local vector_size, is_vector_parsing_complete = read_tl_vector_contents(pinfo, message_tree, buffer, offset, msg_type_name)

        offset = offset + vector_size
        is_parsing_complete = is_vector_parsing_complete
    end

    return offset, is_parsing_complete, info
end

--
-- helper functions
--

function decrypt_message(string_to_decrypt, auth_key_id_number, msg_key, is_outgoing)
    local known_auth_keys = {
        telegram_proto.prefs.auth_key_1, telegram_proto.prefs.auth_key_2, 
        telegram_proto.prefs.auth_key_3, telegram_proto.prefs.auth_key_4,
        telegram_proto.prefs.auth_key_5, telegram_proto.prefs.auth_key_6,
        telegram_proto.prefs.auth_key_7, telegram_proto.prefs.auth_key_8,
        telegram_proto.prefs.auth_key_9, telegram_proto.prefs.auth_key_10,
        telegram_proto.prefs.auth_key_11, telegram_proto.prefs.auth_key_12,
        }

    for index, known_auth_key_hex in ipairs(known_auth_keys) do
        if known_auth_key_hex ~= "" then
            local known_auth_key = key_from_hexstream(known_auth_key_hex)
            local known_auth_key_id = UInt64.decode(sha1_ba(known_auth_key):subset(12, 8):raw(), false)

            if known_auth_key_id == auth_key_id_number then
                -- start decrypting

                local aes_key, aes_iv = get_aes_params_from_keys(known_auth_key, msg_key, is_outgoing)
                -- print("AES KEY (hex):", aes_key:tohex())
                -- print("AES IV (hex):", aes_iv:tohex())

                local decrypted  = aes_ige_decrypt(aes_key:raw(), aes_iv:raw(), string_to_decrypt)

                return decrypted
            else
                -- auth_key_id does not match. not decrypting
                -- maybe add that as a warning to the packet or so
            end
        end  
    end 
end

function read_msg_id_field(pinfo, mtproto_tree, buffer, offset)
    -- https://core.telegram.org/mtproto/description#message-identifier-msg-id

    local msgid_as_uint64 = buffer(offset, 8):uint64():tonumber()

    local msg_id_tree = mtproto_tree:add_le(msg_id_, buffer(offset, 8)); 
    local timestr = os.date("%Y-%m-%d %H:%M:%S", buffer(offset+4, 4):le_uint())
    msg_id_tree:add_le(msg_id_timestamp_, buffer(offset+4, 4)):append_text(" (Corrosponds to " .. timestr .. ")")
    msg_id_tree:add_le(msg_id_fraction_, buffer(offset, 4))
    msg_id_tree:add_le(msg_id_flags_, buffer(offset, 4))

    local res_frame_num = req_msg_ids_to_res_frame[msgid_as_uint64]
    local ack_frame_num = msg_ids_to_ack_packet_numbers[msgid_as_uint64]
    if res_frame_num then
        mtproto_tree:add(response_in_frame_, res_frame_num):set_generated(true)
    end
    if ack_frame_num then
        mtproto_tree:add(ack_in_frame_, ack_frame_num):set_generated(true)
    end

    msg_ids_to_packet_numbers[msgid_as_uint64] = pinfo.number

    return offset + 8
end

function get_aes_params_from_keys(auth_key, msg_key, is_outgoing)
    -- see AuthKey::prepareAES
    -- https://core.telegram.org/mtproto/description#defining-aes-key-and-initialization-vector

    local x = 0
    if not is_outgoing then
        x = 8
    end

    local data_a = msg_key ..  auth_key:subset(x, 36)
    local sha256_a = sha256_ba(data_a)

    local data_b = auth_key:subset(40 + x, 36) .. msg_key
    local sha256_b = sha256_ba(data_b)

    local aesKey = sha256_a:subset(0, 8) .. sha256_b:subset(8, 16) .. sha256_a:subset(24, 8)
    local aesIV = sha256_b:subset(0, 8) .. sha256_a:subset(8, 16) .. sha256_b:subset(24, 8)

    return aesKey, aesIV

end

function detect_transport_protocol(buffer, offset)
    -- https://core.telegram.org/mtproto/mtproto-transports

    local protocol = nil
    local is_obfuscated = false

    if buffer:len() < 4 then
        if buffer(offset, 1):uint() == 0xef and buffer:len() == 1 then
            protocol = "abridged"
        end
        return is_obfuscated, protocol
    end

    local first_word = buffer(offset, 4):string()

    if first_word == "POST" or first_word == "GET " or first_word == "HEAD" or first_word == "OPTI" then
        protocol = "http"
    --elseif first_word == "\x16\x03\01\x00" then
    --    protocol = "tls"
    elseif buffer(offset, 4):uint() == 0xdddddddd then
        protocol = "padded_intermediate"
    elseif buffer(offset, 4):uint() == 0xeeeeeeee then
        protocol = "intermediate"
    elseif buffer(offset, 1):uint() == 0xef and (buffer(offset + 1, 1):uint() * 4 == buffer:len() - 2) then
        protocol = "abridged"
    elseif buffer(offset, 4):le_uint() == buffer:len() then
        protocol = "full"
    else
        -- we'll assume it's obfuscated
        is_obfuscated = true
        local obf_enc_key = buffer(offset + 8, 32):bytes()
        local obf_enc_iv = buffer(offset + 40, 16):bytes()
        local decrypted_bytes = ByteArray.new(deobfuscate(buffer(offset), obf_enc_key, obf_enc_iv, 0, true), true)
        local alledgened_protocol_type = decrypted_bytes:subset(56, 4):raw()

        if alledgened_protocol_type == "\xef\xef\xef\xef" then
            -- good, it's abridged mode
            protocol = "abridged"
        elseif alledgened_protocol_type == "\xdd\xdd\xdd\xdd" then
            protocol = "padded_intermediate"
        elseif alledgened_protocol_type == "\xee\xee\xee\xee" then
            protocol = "intermediate"
        end
    end

    return is_obfuscated, protocol
end

function looks_like_valid_init_payload(buffer, offset)
    local is_obfuscated, detected_protocol = detect_transport_protocol(buffer, offset)
    return detected_protocol ~= nil
end

function dissect_ofbuscation_init_payload(pinfo, tree, buffer, offset, main_tree, connection_key)
    -- https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation
    -- https://github.com/telegramdesktop/tdesktop/blob/472d9dd467055333e281e5f81564fb5096664b13/Telegram/SourceFiles/mtproto/connection_tcp.cpp#L446

    local init_payload_tree = tree:add(buffer(offset, 64), "Obfuscation Initialization Payload")

    init_payload_tree:add(random_bytes_, buffer(offset, 8))
    init_payload_tree:add(enc_obf_key_, buffer(offset + 8, 32))
    init_payload_tree:add(enc_obf_iv_, buffer(offset + 40, 16))
    init_payload_tree:add(enc_fields_, buffer(offset + 56, 8))

    tree:add(enc_msg_, buffer(offset + 64))

    local obf_enc_key = buffer(offset + 8, 32):bytes()
    local obf_enc_iv = buffer(offset + 40, 16):bytes()

    local decrypted_bytes = deobfuscate(buffer(offset), obf_enc_key, obf_enc_iv, 0, true)
    local dec_data = ByteArray.new(decrypted_bytes, true):tvb("Deobfuscated MTProto data")
    local subtree_dec = main_tree:add(dec_data(), "Deobfuscated data")

    local int_payload_dec_tree = subtree_dec:add(dec_data(offset, 64), "Initialization Payload")
    int_payload_dec_tree:add(random_bytes_, dec_data(offset, 56))
    local protocol_type_tree = int_payload_dec_tree:add(protocol_type_, dec_data(offset + 56, 4))
    int_payload_dec_tree:add_le(dc_id_, dec_data(offset + 60, 2))
    int_payload_dec_tree:add(random_bytes_, dec_data(offset + 62, 2))

    local reversed_init_payload = reverse_tvb(buffer(8, 48))
    local obf_dec_key = reversed_init_payload(0, 32)
    local obf_dec_iv = reversed_init_payload(32, 16)

    connection_infos[connection_key]["obf_enc_key"] = obf_enc_key
    connection_infos[connection_key]["obf_enc_iv"] = obf_enc_iv
    connection_infos[connection_key]["obf_dec_key"] = obf_dec_key
    connection_infos[connection_key]["obf_dec_iv"] = obf_dec_iv
    connection_infos[connection_key]["num_bytes_processed"] = decrypted_bytes:len()

    if _protocol_type()() == 0xefefefef then
        connection_infos[connection_key]["protocol"] = "abridged"
        protocol_type_tree:append_text(" [abridged]")
    elseif _protocol_type()() == 0xdddddddd then
        connection_infos[connection_key]["protocol"] = "padded_intermediate"
        protocol_type_tree:append_text(" [Padded Intermediate]")
    elseif _protocol_type()() == 0xeeeeeeee then
        connection_infos[connection_key]["protocol"] = "intermediate"
        protocol_type_tree:append_text(" [Intermediate]")
    end

    offset = 64

    local tcp_payload = tcp_payload_field()
    local tcp_payload_start = tcp_payload.offset -- ← this is the key!
    local relative_tcp_offset = buffer:offset() - tcp_payload_start -- in case of multiple protocol layers, tells you the offset to this layer
    local frames_count = 0
    local info = ""

    offset, frames_count, info =  dissect_mtproto_frames(pinfo, subtree_dec, connection_infos[connection_key], dec_data, offset, 0, true)

    append_pinfo_string(pinfo, info)

    return offset
end


function key_from_hexstream(s)
    local key_bytearray = ByteArray.new(s)
    --local key_tvb = ByteArray.tvb(key_bytearray, "tmp")
    --local key_tvb_range = key_tvb(0, key_bytearray:len())
    return key_bytearray
end


local gcrypt = require("luagcrypt")

function deobfuscate(buffer, key, iv, bytes_count, is_outgoing)

    local cipher = gcrypt.Cipher(gcrypt.CIPHER_AES256, gcrypt.CIPHER_MODE_CTR)
    local is_initial = packets_count == 0
    local ciphertext = buffer:raw()

    iv = increment_bytearray(iv, bytes_count / 16)

    cipher:setkey(key:raw())
    cipher:setctr(iv:raw())

    cipher:decrypt(ByteArray.new(string.rep("\x00", bytes_count % 16), true):raw())

    return cipher:decrypt(ciphertext)
end


--
-- Register dissector for TCP traffic
--
local tcp_table = DissectorTable.get("tcp.port")
for port, _ in pairs(telegram_ports) do
    tcp_table:add(port, telegram_proto)
end


--
-- utilities
--

-- XOR two 16-byte strings
local function xor_block(a, b)
    assert(#a == #b, "xor_block(): mismatched lengths")

    local out = {}
    for i = 1, #a do
        local byteA = string.byte(a, i)
        local byteB = string.byte(b, i)

        local x = bit.bxor(byteA, byteB)

        out[i] = string.char(x)
    end
    return table.concat(out)
end

-- XOR two 16-byte strings
local function xor_16_bytes_block(a, b)
    -- doing it this way is about X3 faster than doing it in a loop
    local a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16 = string.byte(a,1,16)
    local b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11,b12,b13,b14,b15,b16 = string.byte(b,1,16)
    local tmp = string.char(
        bit.bxor(a1,b1), bit.bxor(a2,b2), bit.bxor(a3,b3), bit.bxor(a4,b4),
        bit.bxor(a5,b5), bit.bxor(a6,b6), bit.bxor(a7,b7), bit.bxor(a8,b8),
        bit.bxor(a9,b9), bit.bxor(a10,b10), bit.bxor(a11,b11), bit.bxor(a12,b12),
        bit.bxor(a13,b13), bit.bxor(a14,b14), bit.bxor(a15,b15), bit.bxor(a16,b16)
    )
    return tmp
end




-- https://mgp25.com/blog/2015/06/21/AESIGE

-- AES-IGE decrypt
-- key: string (16/24/32 bytes)
-- iv:  string (32 bytes = 2×block size)
-- data: string (ciphertext, multiple of 16 bytes)
-- returns: plaintext string
function aes_ige_decrypt(key, iv, data)
    assert(#iv == 32, "IV must be 32 bytes for IGE mode")
    assert(#data % 16 == 0, "data length must be multiple of 16, it's " .. #data)

    local xPrev = iv:sub(1, 16)
    local yPrev = iv:sub(17, 32)

    -- Create AES context in ECB mode
    local ctx = gcrypt.Cipher(gcrypt.CIPHER_AES256, gcrypt.CIPHER_MODE_ECB, 0)
    ctx:setkey(key)

    local plaintext = {}
    local nblocks = math.floor(#data / 16)

    for i = 0, nblocks - 1 do
        local x = data:sub(i*16 + 1, i*16 + 16)

        -- D_i = AES-DEC(C_i XOR IV1)
        local yXOR = xor_16_bytes_block(x, yPrev)
        local yFinal = ctx:decrypt(yXOR)
        -- $yFinal = str_pad($yFinal, strlen($xPrev), "\x00");?

        -- P_i = D_i XOR IV2
        local y = xor_16_bytes_block(yFinal, xPrev)

        table.insert(plaintext, y)

        -- update IVs for next block
        xPrev = x
        yPrev = y
    end

    
    return table.concat(plaintext)
end

-- AES-IGE encrypt (for completeness)
function aes_ige_encrypt(key, iv, data)
    assert(#iv == 32, "IV must be 32 bytes for IGE mode")
    assert(#data % 16 == 0, "data length must be multiple of 16")

    local iv1 = iv:sub(1, 16)
    local iv2 = iv:sub(17, 32)

    local ctx = gcrypt.Cipher(gcrypt.CIPHER_AES256, gcrypt.CIPHER_MODE_ECB, 0)
    ctx:setkey(key)

    local ciphertext = {}
    local nblocks = math.floor(#data / 16)

    for i = 0, nblocks - 1 do
        local P_i = data:sub(i*16 + 1, i*16 + 16)

        -- X = P_i XOR IV2
        local X = xor_block(P_i, iv2)
        -- Y = AES-ENC(X)
        local Y = ctx:encrypt(X)
        -- C_i = Y XOR IV1
        local C_i = xor_block(Y, iv1)

        table.insert(ciphertext, C_i)

        -- update IVs for next block
        iv2 = C_i
        iv1 = P_i
    end

    
    return table.concat(ciphertext)
end


function append_pinfo_string(pinfo, str)
    if str == nil or str == "" then
        return str
    end

    if tcp_segment_count() ~= nil then
        -- this might mean this is another MTPRoto layer over an existing layer
        -- what do we write in this case?
        pinfo.cols.info = " + " .. str
        return
    end

    local nothing_in_pinfo_yet = tostring(pinfo.cols.info):endswith(": ") or tostring(pinfo.cols.info):len() < 18

    if nothing_in_pinfo_yet then
        pinfo.cols.info = tostring(pinfo.cols.info) .. str
    else
        pinfo.cols.info = tostring(pinfo.cols.info) .. ", " .. str
    end
end

function append_to_string(str, addition)
    if addition == nil or addition == "" then
        return str
    end

    if tostring(str):len() > 1 then
        str = str .. ", " .. addition
    else
        str = addition
    end

    return str
end

function looks_like_decimal_id_param(param_name)
    return param_name:endswith("id") and not param_name:endswith("key_id") and not param_name:endswith("msg_id") and not param_name:endswith("ping_id")
end

function check_for_uncompress_zlib()
    -- Safe test: try to fetch the method from the metatable
    local ok, fn = pcall(function()
        return TvbRange.uncompress_zlib
    end)
    return ok and type(fn) == "function"
end

local has_uncompress_zlib = check_for_uncompress_zlib()


function decompress_gzip(gzip_compressed_tvb)

    if has_uncompress_zlib then
        local decompressed_tvb = gzip_compressed_tvb:uncompress_zlib()
        return decompressed_tvb
    else
        local decompressed_tvb = gzip_compressed_tvb:uncompress()
        return decompressed_tvb
    end
end

function reverse_tvb(tvb_range, name)
    -- Step 1: Convert tvb to ByteArray
    local ba = tvb_range:bytes()

    -- Step 2: Read bytes from ByteArray and reverse them
    local len = ba:len()
    local reversed_ba = ByteArray.new()
    for i = len - 1, 0, -1 do
        reversed_ba:append(ba:subset(i, 1))  -- append 1-byte string
    end

    return reversed_ba
end

function bytearray_to_uint64_be(ba)
    assert(ba:len() >= 8, "ByteArray too short for uint64")

    local result = 0
    for i = 0, 7 do
        result = result * 256 + ba:get_index(i)
    end
    return result
end

-- CRC32 (IEEE) table generation using bit32
local crc32_table = {}

do
    for i = 0, 255 do
        local crc = i
        for _ = 1, 8 do
            local mask = bit.band(crc, 1)
            crc = bit.rshift(crc, 1)
            if mask == 1 then
                crc = bit.bxor(crc, 0xEDB88320)
            end
        end
        crc32_table[i] = crc
    end
end

-- Compute CRC32 over a ByteArray-like object (tvb range also works)
-- buf must support buf(i,1):uint()
function crc32(buf)
    local crc = 0xFFFFFFFF

    for i = 0, buf:len() - 1 do
        local byte = buf(i,1):uint()
        local idx  = bit.bxor(crc, byte) % 256
        crc = bit.bxor(bit.rshift(crc, 8), crc32_table[idx])
    end

    return bit.bxor(crc, 0xFFFFFFFF)
end
  

-- Helper: SHA256 / SHA1 wrappers returning ByteArray
function sha1_ba(data_ba)
    local md = gcrypt.Hash(gcrypt.MD_SHA1)

    md:write(data_ba:raw())  -- raw() -> string of bytes
    local hash = md:read(gcrypt.MD_SHA1)
    local hash_hexstring = (hash:gsub('.', function(c) return string.format('%02X', c:byte()) end))
    return ByteArray.new(hash_hexstring)
end

function sha256_ba(data_ba)
    local md = gcrypt.Hash(gcrypt.MD_SHA256)

    md:write(data_ba:raw())  -- raw() -> string of bytes
    local hash = md:read(gcrypt.MD_SHA256)
    local hash_hexstring = (hash:gsub('.', function(c) return string.format('%02X', c:byte()) end))
    return ByteArray.new(hash_hexstring)
end

function split(str, sep)
    local result = {}
    for part in string.gmatch(str, "([^" .. sep .. "]+)") do
        table.insert(result, part)
    end
    return result
end


function increment_bytearray(iv_ba, blocks)
    blocks = blocks or 1
    local len = iv_ba:len()
    local result = ByteArray.new(iv_ba:raw(), true)  -- clone it so we don't mutate original

    local carry = blocks
    for i = len - 1, 0, -1 do  -- start at last byte (big-endian)
        local val = result:get_index(i) + carry
        result:set_index(i, math.floor(val % 256))
        carry = math.floor(val / 256)
        if carry == 0 then break end
    end

    return result
end

-- Create a consistent, bidirectional connection key
function get_normalized_connection_key(pinfo)
    local ip1, port1 = tostring(src_ipv4()), tonumber(pinfo.src_port)
    local ip2, port2 = tostring(dst_ipv4()), tonumber(pinfo.dst_port)

    if ip1 < ip2 or (ip1 == ip2 and port1 <= port2) then
        return ip1 .. ":" .. port1 .. "-" .. ip2 .. ":" .. port2
    else
        return ip2 .. ":" .. port2 .. "-" .. ip1 .. ":" .. port1
    end
end

function get_packet_key()
    local is_multi_layer = tcp_segment_count() ~= nil
    if not is_multi_layer then
        return tcp_seq_num_raw()()
    else
        return tostring(tcp_seq_num_raw()()) .. ".1"
    end
end

function is_all_ascii(s)
    -- TODO: we can do looks_like_utf8
    for i = 1, #s do
      local byte_value = string.byte(s, i)
      if byte_value > 127 or byte_value < 10 then
        return false -- Found a non-ASCII/printable character
      end
    end
    return true -- All characters are ASCII
end

function string:endswith(suffix)
    return suffix == "" or self:sub(-#suffix) == suffix
end


function get_script_path()
    local str = debug.getinfo(2, "S").source:sub(2)
    return str:match("(.*[/\\])")
end
  
function json_to_table(json_str)
    -- L="return ".. json:gsub('("[^"]-"):','[%1]=') 
    -- return loadstring(L)()
    return json.decode(json_str)
end