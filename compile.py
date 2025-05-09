import json


def pack_locals(d: dict[str, str]) -> str:
    return "\n".join([f"local {name} = {value}" for name, value in d.items()])


def generate_list(l: list[str]) -> str:
    if len(l) == 0:
        return "{}"
    return "{\n    [0] = " + ",\n    ".join([f'"{element}"' for element in l]) + ",\n}"


def generate_int_str_dict(d: dict[int, str]) -> str:
    if len(d) == 0:
        return "{}"
    return "{\n    " + ",\n    ".join([f'[{k}] = "{v}"' for k, v in d.items()]) + ",\n}"


def generate_int_int_dict(d: dict[int, int]) -> str:
    if len(d) == 0:
        return "{}"
    return "{\n    " + ",\n    ".join([f"[{k}] = {v}" for k, v in d.items()]) + ",\n}"


with open("RoveComm_Base/manifest.json", "r", newline="") as f:
    manifest = json.load(f)

with open("source.lua", "r", newline="") as f:
    source = f.read()

ips = {}
names = {}
types = {}
counts = {}
comments = {}

for board_name, board in manifest["RovecommManifest"].items():
    if "Ip" in board:
        ip = board["Ip"]
    else:
        ip = "0.0.0.0"

    for packet_type in ["Commands", "Telemetry", "Error"]:
        if packet_type in board:
            for packet_name, packet_desc in board[packet_type].items():
                data_id = packet_desc["dataId"]
                ips[data_id] = ip
                names[data_id] = f"{board_name}.{packet_type}.{packet_name}"
                types[data_id] = manifest["DataTypes"][packet_desc["dataType"]]
                counts[data_id] = packet_desc["dataCount"]
                comments[data_id] = packet_desc["comments"]

with open("rovecomm.lua", "w", newline="") as f:
    f.write("-- Start generated code\n")
    f.write(
        pack_locals(
            {
                "DATA_TYPE_NAMES": generate_list(manifest["DataTypes"].keys()),
                "DATA_TYPE_SIZES": generate_list(manifest["dataSizes"]),
                "SYSTEM_PACKETS": generate_int_str_dict(
                    {
                        data_id: name
                        for name, data_id in manifest["SystemPackets"].items()
                    }
                ),
                "IPS": generate_int_str_dict(ips),
                "NAMES": generate_int_str_dict(names),
                "TYPES": generate_int_int_dict(types),
                "COUNTS": generate_int_int_dict(counts),
                "COMMENTS": generate_int_str_dict(comments),
            }
        )
    )
    f.write("\n-- End generated code\n\n")
    f.write(source)
