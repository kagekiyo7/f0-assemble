import argparse
import os

parser = argparse.ArgumentParser(description="Keitai M4 Assemble (incomplete)")
parser.add_argument("input")
parser.add_argument("output")

args = parser.parse_args()

os.makedirs(args.output, exist_ok=True)

def detect_extension(data, pre_ext):
    if pre_ext == "jar":
        return "sp"
    elif pre_ext == "sp":
        return "adf"
    elif data[0:4] == b"\x50\x4B\x03\x04":
        return "jar"
    elif (
         data[0:4] == b"\xFF\xD8\xFF\xDB"
         or data[0:4] == b"\xFF\xD8\xFF\xEE"
         or data[0:0xC] == b"\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01"
         or (data[0:4] == b"\xFF\xD8\xFF\xE1" and data[6:0xC] == b"\x45\x78\x69\x66\x00\x00")
       ):
        return "jpg"
    else:
        return None
    

vspace = {}
with open(args.input, "rb") as file:
    data = file.read(0x20000)
    block_number = 0
    while len(data) > 0:
        if data[0x1FFF9:0x1FFFE] == b"\x55\x55\x55\xFF\xFF":
            off = 0
            while data[off : off + 0x10] != b"\xFF" * 0x10:
                chunk_id = data[off+2]
                fs = int.from_bytes(data[off + 3 : off + 5], "little")
                loc = int.from_bytes(data[off + 8 : off + 0xA], "little")
                size = int.from_bytes(data[off + 0xC : off + 0x10], "little")
                vspace[fs] = vspace.get(fs, {})
                
                # if fs == 288:
                    # print(
                        # hex(block_number+off) + ":"
                        # , " ".join([f"{byte:0=2X}" for byte in data[off + 0 : off + 0x10]]) 
                        # , f"(chunk_id={hex(chunk_id)}, {size=})"
                    # )
                
                # assert chunk_id not in vspace[fs], (
                    # fs, hex(block_number) + " " + hex(off) + str(data[off + 0 : off + 0x10])
                # )
                
                if chunk_id in vspace[fs]:
                    print(f"WARN: chunk_id {chunk_id} of fs {fs} is duplicated. ({hex(block_number + off)})")
                
                vspace[fs][chunk_id] = data[
                    0x1FFE0 - (loc * 0x80) : 0x1FFE0 - (loc * 0x80) + size
                ]
                off += 0x10
        data = file.read(0x20000)
        block_number += 0x20000

pre_ext = None
ext = None

for fs, fs_v in sorted(vspace.items(), key=lambda x:int(x[0])):
    data = bytearray()
    for ch, ch_v in sorted(fs_v.items(), key=lambda x:int(x[0])):
        data += ch_v
    
    ext = detect_extension(data, pre_ext) or "bin"
    
    #print(f"region_{fs:04d}.{ext}")
    with open(os.path.join(args.output, f"region_{fs:05d}.{ext}"), "wb") as file:
        file.write(data)
    
    pre_ext = ext
