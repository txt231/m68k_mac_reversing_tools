import struct
import ctypes
import io
import machfs
import macresources
import collections

import vise

# make custom jank dump of code

SYSTEM_RAM_SIZE = 0x10000
DUMMY_ADDR = 0xFFFFFFFF


# m68k is big endian
def u16(x):
    return struct.unpack(">H", x)[0]


def u16s(x):
    return struct.unpack(">h", x)[0]


def u32(x):
    return struct.unpack(">I", x)[0]


def p16(x):
    return struct.pack(">H", x)


def p32(x):
    return struct.pack(">I", x)


def u16_to_s16(x):
    if x & 0x8000:
        x -= 0x10000
    return x


CALLBACK_LOADSEG = 0xAF90


class JmpEntry(ctypes.BigEndianStructure):
    _fields_ = (
        ("segment_offset", ctypes.c_uint16),
        ("type", ctypes.c_uint16),
        ("segment_idx", ctypes.c_uint16),
        ("callback", ctypes.c_uint16),
    )  # 0x0008

    def isUnloaded(self):
        return self.type == 0x3F3C

    def isPreloaded(self):
        return self.type == 0x4EED

    def isDynamic(self):
        return self._0x0000 == 0xA89F

    def __str__(self) -> str:
        return "(0x%04x, 0x%04x | 0x%04x, 0x%04x)" % (
            self.type,
            self.segment_idx,
            self.segment_offset,
            self.callback,
        )

    def __repr__(self) -> str:
        return self.__str__()


class CodeHeader(ctypes.BigEndianStructure):
    _fields_ = (
        ("above_a5_size", ctypes.c_uint32),  # 0x0000
        ("below_a5_size", ctypes.c_uint32),  # 0x0004
        ("jumptable_size", ctypes.c_uint32),  # 0x0008
        ("jumptable_offset", ctypes.c_uint32),  # 0x000c
        ("_0x0010", ctypes.c_uint32),  # 0x0010
        ("_0x0014", ctypes.c_uint32),  # 0x0014
        ("jmptable_type", ctypes.c_uint16),  # 0x0018
        ("base_segment_offset", ctypes.c_uint16),  # 0x001a
        ("segment_idx", ctypes.c_uint16),  # 0x001c
        ("base_segment_size", ctypes.c_uint8),  # 0x001e
        ("_0x001f", ctypes.c_uint8),  # 0x001f
    )  # 0x0020


def build_jumptable(header: CodeHeader, jumptable: bytes):
    Entries = []

    if header.jmptable_type != 0xA89F:
        Buf = io.BytesIO(jumptable[0x10:])

        for _ in range(0, header.jumptable_size, 8):
            Entries.append(JmpEntry.from_buffer_copy(Buf.read(0x8)))

        return Entries

    Ent = JmpEntry()
    Ent.segment_offset = header.base_segment_offset
    Ent.type = 0x3F3C
    Ent.segment_idx = header.segment_idx
    Ent.callback = CALLBACK_LOADSEG
    Entries.append(Ent)  # this causes issues and misalignment.
    Entries.append(Ent)  # doubler up to fix alignment?

    SegNum = header.segment_idx
    SegOffset = header.base_segment_offset
    # SegSize = jumptable[0x1E:]
    SegSize = io.BytesIO(jumptable[0x1F:])

    # SegSize = SegSize[1:]

    # this reminds me very much of some lz algorithm
    for _ in range(8 * 3, header.jumptable_size, 8):
        b1 = SegSize.read(1)[0]

        if (b1 & 0x80) == 0:
            SegOffset += (b1 & 0xFF) * 2
            SegOffset &= 0xFFFF

            Ent = JmpEntry()
            Ent.segment_offset = SegOffset
            Ent.type = 0x3F3C
            Ent.segment_idx = SegNum
            Ent.callback = CALLBACK_LOADSEG
            Entries.append(Ent)

        else:
            SegOffset = ((b1 & 0x7F) << 8) | SegSize.read(1)[0]

            if (SegOffset & 1) == 0:
                Ent = JmpEntry()
                Ent.segment_offset = SegOffset
                Ent.type = 0x3F3C
                Ent.segment_idx = SegNum
                Ent.callback = CALLBACK_LOADSEG

                Entries.append(Ent)
                continue

            # clear first bit
            SegOffset &= 0x7FFE

            SegNum = struct.unpack(">H", SegSize.read(2))[
                0
            ]  # (SegSize[0] << 8) | SegSize[1]

            Ent = JmpEntry()
            Ent.segment_offset = SegOffset
            Ent.type = 0x3F3C
            Ent.segment_idx = SegNum
            Ent.callback = CALLBACK_LOADSEG

            Entries.append(Ent)

    return Entries


def dump_image(image_filename, path, out_filepath):
    with open(image_filename, "rb") as f:
        flat = f.read()
        v = machfs.Volume()
        v.read(flat)
        print(v)
        for i in path:
            v = v[i]
        resData = v.rsrc

        rsrcs = collections.defaultdict(dict)
        for i in macresources.parse_file(resData):
            print(i)
            rsrcs[i.type][i.id] = i

        return dump_resoruces(rsrcs, out_filepath)

    return None


def dump_file(path, out_filepath):
    rsrcs = collections.defaultdict(dict)
    for i in macresources.parse_rez_code(open(path, "rb").read()):
        print(str(i)[:100])
        rsrcs[i.type][i.id] = i

    return dump_resoruces(rsrcs, out_filepath)


def dump_resoruces(rsrcs, out_filename):
    for i in rsrcs:
        print(i)
        for j, r in rsrcs[i].items():
            if r.name != None:
                print(f"    {j}: {r.name}")
            else:
                print(f"    {j}")

    if b"CODE" not in rsrcs:
        print("Error: no executable code?")
        return

    # TODO: other resource types

    codes = rsrcs[b"CODE"]
    crels = rsrcs[b"CREL"]

    ViseData = vise.scan_vise(codes)
    if ViseData != None:
        print("This binary is vise compressed!")

    jumptable = bytes(codes[0])

    print(jumptable, len(jumptable))
    header = CodeHeader.from_buffer_copy(
        jumptable + bytes([0] * 100)
    )  # NOTE: gheeto fix for header size stuff
    jumptable_ents = build_jumptable(header, jumptable)

    for x in jumptable_ents:
        print(x)

    assert header.jumptable_offset == 0x20

    a5 = header.below_a5_size + SYSTEM_RAM_SIZE
    #     a5 += len(rsrcs[b"STRS"][0])

    dump = io.BytesIO()
    junkHeader = (
        b"J\xffA\xffN\xffK\xff"  # put garbage so address 0 isn't recognized as a string
    )

    # small function to force binary ninja to set the value of a5 as a global reg
    # move.l #a5_value, a5
    # rts
    junkHeader += b"\x2a\x7c" + p32(a5) + b"\x4e\x75"

    system_ram = bytearray(junkHeader + bytes(SYSTEM_RAM_SIZE - len(junkHeader)))

    # NOTE: we fix theese later after writing data
    # system_ram[0x904:0x908] = p32(a5)
    # dump += system_ram
    dump.write(system_ram)

    strs_base = 0
    if b"STRS" in rsrcs:
        strs_base = dump.tell()

        # TODO: decompress string table
        a5 += len(rsrcs[b"STRS"][0])
        dump.write(rsrcs[b"STRS"][0])
        # dump += rsrcs[b"STRS"][0]

    segment_bases = {}
    for i in codes:
        if i == 0:
            continue

        codeData = codes[i]

        if vise.is_compressed(codeData):
            codeData = vise.decompress(codeData, ViseData)

            if codeData == None:
                print("failed decompressing ?!")
                continue
            print("decompressed data!")

        segment_header = codeData[:4]
        segment_data = bytearray(codeData[4:])

        segment_bases[i] = dump.tell()

        first_jumptable_entry_offset = u16(segment_header[:2])
        needs_relocations = False
        if first_jumptable_entry_offset & 0x8000:
            first_jumptable_entry_offset &= ~0x8000
            needs_relocations = True
        jumptable_entry_num = u16(segment_header[2:])
        far_header = False
        if jumptable_entry_num & 0x8000:
            jumptable_entry_num &= ~0x8000
            far_header = True
        print(
            f"code segment {i}: first offset {first_jumptable_entry_offset:04x}, {jumptable_entry_num} jumptable entries",
            end="",
        )
        if needs_relocations:
            print(", reloc", end="")
        if far_header:
            print(", far", end="")
        print()
        # Think C (Symantec) relocations
        if needs_relocations and jumptable_entry_num > 0:
            # TODO: refactor
            if i < len(crels):
                for j in range(0, len(crels[i]), 2):
                    addr = u16(crels[i][j : j + 2]) - 4  # -4 from header
                    if addr & 0x1:
                        print("STRS patch ", end="")
                        base = strs_base
                        addr = addr & 0xFFFE
                    else:
                        print("A5 patch ", end="")
                        base = a5
                    data = u32(segment_data[addr : addr + 4])
                    data2 = (data + base) & 0xFFFFFFFF
                    segment_data[addr : addr + 4] = p32(data2)
                    print(f"seg {i} addr {addr:04x} ({data:08x} -> {data2:08x})")

        while (dump.tell() % 0x10) != 0:
            a5 += 1
            dump.write(bytes([0]))
        a5 += len(segment_data)
        dump.write(bytes(segment_data))
        # dump += bytes(segment_data)

    # construct a5 world
    a5_world = b"\x00" * 32  # TODO pointer to quickdraw global vars
    for ent in jumptable_ents:
        segment_num = 0
        addr = DUMMY_ADDR
        if ent.isUnloaded():
            """
            unloaded jumptable entry structure:
                XX XX: segment offset
                3f 3c XX XX: move.w SEGMENT_NUMBER, -(SP)
                    pushes SEGMENT_NUMBER onto the stack for _LoadSeg trap
                a9 f0: _LoadSeg trap number
            """

            if ent.segment_idx in segment_bases:
                addr = segment_bases[ent.segment_idx] + ent.segment_offset
            else:
                print(
                    "Code segment %i not found for jumptable entry [%s], using dummy"
                    % (ent.segment_idx, ent)
                )
        elif ent.isPreloaded():
            """
            preloaded? jumptable entry structure:
                XX XX: ???
                4e ed XX XX: jmp OFFSET(a5)
                4e 71: nop
            """
            addr = ent.segment_idx + a5
        else:
            print("jumptable entry [0x%04x] not known, using dummy" % (ent.type))

        # TODO: ghidra doesnt want to disassemble jmp? version diffrence of slaspecs??
        a5_world += p16(segment_num)
        a5_world += b"\x4e\xf9"  # jmp
        a5_world += p32(addr)

    below_a5_data = bytes(header.below_a5_size)

    if b"ZERO" in rsrcs and b"DATA" in rsrcs:
        data_rsrc = bytes(rsrcs[b"DATA"][0])
        zero_rsrc = bytes(rsrcs[b"ZERO"][0])
        total_data_size = len(data_rsrc)
        for i in range(0, len(zero_rsrc), 2):
            total_data_size += u16(zero_rsrc[i : i + 2])
        if total_data_size <= header.below_a5_size:
            print("Adding DATA below A5 world")
            below_a5_data = bytearray()
            zero_index = 0
            for i in range(0, len(data_rsrc), 2):
                below_a5_data += data_rsrc[i : i + 2]
                if u16(data_rsrc[i : i + 2]) == 0:
                    below_a5_data += bytes(u16(zero_rsrc[zero_index : zero_index + 2]))
                    zero_index += 2
            # TODO refactor
            drel_rsrc = bytes(rsrcs[b"DREL"][0])
            i = 0
            while i < len(drel_rsrc):
                addr = u16s(drel_rsrc[i : i + 2])
                if addr >= 0:
                    i += 2
                    addr = -u16(drel_rsrc[i : i + 2])
                if addr & 0x1:
                    print("STRS patch ", end="")
                    base = strs_base
                    addr = u16_to_s16(addr & 0xFFFE)
                else:
                    print("A5 patch ", end="")
                    base = a5
                addr += header.below_a5_size  # DREL relative to a5
                data = u32(below_a5_data[addr : addr + 4])
                data2 = (data + base) & 0xFFFFFFFF
                below_a5_data[addr : addr + 4] = p32(data2)
                print(f"data addr {addr:04x} ({data:08x} -> {data2:08x})")
                i += 2
            below_a5_data = bytes(below_a5_data) + bytes(
                header.below_a5_size - total_data_size
            )

    while (a5 % 0x10) != 0:
        a5 += 1

    # write a5
    LastPos = dump.tell()
    dump.seek(0x8 + 0x2, io.SEEK_SET)
    dump.write(p32(a5))

    # system_ram[0x904:0x908] = p32(a5)
    dump.seek(0x904, io.SEEK_SET)
    dump.write(p32(a5))

    dump.seek(LastPos, io.SEEK_SET)

    # dump += below_a5_data
    dump.write(below_a5_data)
    # assert len(dump) == a5
    if dump.tell() < a5:
        dump.write(bytes([0] * (a5 - dump.tell())))

    # dump += a5_world
    print("adding a5_world at 0x%x" % dump.tell())
    dump.write(a5_world)

    while (dump.tell() % 0x100) != 0:
        dump.write(bytes([0]))

    dump.seek(0, io.SEEK_SET)
    OutDump = dump.read()

    open(out_filename, "wb").write(OutDump)


# dump_file('HeavenEarth13Color.toast', ['Heaven & Earth'], 'dump_heavenandearth')
# dump_file('disk2.dsk', ["System's Twilight"], 'dump_systemstwilight')
# dump_file("testfile.bin", ["Kid Pix"], "dump_kidpix")

# dump_file(
#     "/home/txt/Documents/RE/apple/data/data/System Folder/Control Panels/Monitors & Sound.rdump",
#     "dump_monitorsound_2",
# )

dump_file(
    "/home/txt/Documents/RE/apple/data/data2/serviceutils/Display Service Utility 4.1.1/Display Service Utility.rdump",
    "dump_dsu3_decomp3",
)
