-- Unfortunately hardcoded and not derived from the manifest.
local DATA_TYPE_TYPES = {
    [0] = ftypes.INT8,
    ftypes.UINT8,
    ftypes.INT16,
    ftypes.UINT16,
    ftypes.INT32,
    ftypes.UINT32,
    ftypes.FLOAT,
    ftypes.DOUBLE,
    ftypes.CHAR
}

local DATA_TYPE_FIELDS = {}

rove_protocol = Proto("RoveComm", "Mars Rover Design Team RoveComm")

version_field = ProtoField.uint8("rove.version", "version", base.DEC)
data_id_field = ProtoField.uint16("rove.data_id", "dataId", base.DEC)
data_count_field = ProtoField.uint16("rove.data_count", "dataCount", base.DEC)
data_type_field = ProtoField.uint8("rove.data_type", "dataType", base.DEC)
data_field = ProtoField.bytes("rove.data", "data")
rove_protocol.fields = { version_field, data_id_field, data_count_field, data_type_field, data_field }

for data_type_number = 0, 8 do
    DATA_TYPE_FIELDS[data_type_number] = ProtoField.new(DATA_TYPE_NAMES[data_type_number],
        "rove." .. DATA_TYPE_NAMES[data_type_number], DATA_TYPE_TYPES[data_type_number])
    table.insert(rove_protocol.fields, DATA_TYPE_FIELDS[data_type_number])
end

local expert_bad_data_id = ProtoExpert.new(
    "BadDataId",
    "The encoded data_id does not exist in the manifest",
    expert.group.MALFORMED,
    expert.severity.WARN
)
local expert_bad_length = ProtoExpert.new(
    "BadLength",
    "The encoded data_count does not equal the actual length",
    expert.group.MALFORMED,
    expert.severity.WARN
)
local expert_manifest_count_mismatch = ProtoExpert.new(
    "ManifestCountMismatch",
    "The encoded data_count does not match the manifest for this data_id",
    expert.group.MALFORMED,
    expert.severity.WARN
)
local expert_bad_data_type = ProtoExpert.new(
    "BadDataType",
    "The data_type does not exist in the manifest",
    expert.group.MALFORMED,
    expert.severity.ERROR
)
local expert_manifest_type_mismatch = ProtoExpert.new(
    "ManifestTypeMismatch",
    "The encoded data_type does not match the manifest for this data_id",
    expert.group.MALFORMED,
    expert.severity.WARN
)
rove_protocol.experts = {
    expert_bad_data_id,
    expert_bad_length,
    expert_manifest_count_mismatch,
    expert_bad_data_type,
    expert_manifest_type_mismatch,
}

function rove_protocol.dissector(buffer, pinfo, tree)
    if buffer:captured_len() < 5 then return end

    pinfo.cols.protocol = rove_protocol.name

    -- Create a new subtree named "RoveComm Protocol Data".
    local subtree = tree:add(rove_protocol, buffer(), "RoveComm Protocol Data")

    -- Add header fields.
    subtree:add(version_field, buffer(0, 1))
    local data_id = buffer(1, 2):uint()
    subtree:add(data_id_field, buffer(1, 2)):append_text(" (" ..
        (SYSTEM_PACKETS[data_id] or NAMES[data_id] or "Unknown") .. ")")
    local data_count_number = buffer(3, 2):uint()
    subtree:add(data_count_field, buffer(3, 2))
    local data_type_number = buffer(5, 1):uint()
    subtree:add(data_type_field, buffer(5, 1)):append_text(" (" ..
        (DATA_TYPE_NAMES[data_type_number] or "Unknown") .. ")")

    if (DATA_TYPE_NAMES[data_type_number] == nil) then
        -- Data type number is invalid, add the unparsed data.
        subtree:add_proto_expert_info(expert_bad_data_type)
        Dissector.get("data"):call(buffer(6):tvb(), pinfo, tree)
    else
        -- Add parsed data.
        local data_type_size = DATA_TYPE_SIZES[data_type_number];
        local actual_data_length = buffer:reported_len() - 6
        local expected_data_length = data_type_size * data_count_number
        local data_subtree = subtree:add(data_field, buffer(6));
        for i = 0, data_count_number - 1 do
            data_subtree:add(DATA_TYPE_FIELDS[data_type_number], buffer(6 + i * data_type_size, data_type_size));
        end
        if (actual_data_length ~= expected_data_length) then subtree:add_proto_expert_info(expert_bad_length) end
    end

    -- Add warnings
    if NAMES[data_id] == nil then
        if SYSTEM_PACKETS[data_id] == nil then subtree:add_proto_expert_info(expert_bad_data_id) end
    else
        if COUNTS[data_id] ~= data_count_number then
            subtree:add_proto_expert_info(expert_manifest_count_mismatch,
                "The encoded data_count does not match the manifest for this data_id (" ..
                tostring(COUNTS[data_id]) .. ")")
        end
        if TYPES[data_id] ~= data_type_number then
            subtree:add_proto_expert_info(expert_manifest_type_mismatch,
                "The encoded data_type does not match the manifest for this data_id (" ..
                tostring(TYPES[data_id]) .. " " .. DATA_TYPE_NAMES[TYPES[data_id]] .. ")")
        end
    end
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(12000, rove_protocol)

local udp_port = DissectorTable.get("udp.port")
udp_port:add(11000, rove_protocol)
