#!/usr/bin/python

"""
Protod, version 1.1 - Generic version

Copyright (c) 2012 SYSDREAM


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Author: Damien Cauquil <d.cauquil@sysdream.com>

"""

import os
import sys
from enum import Enum
from typing import Callable, Sequence, Tuple, Union

# require google's protobuf library
from google.protobuf.descriptor_pb2 import (DescriptorProto,
                                            FieldDescriptorProto,
                                            FileDescriptorProto)
from google.protobuf.message import DecodeError

from util import check_files

###########
# helpers
###########


# See https://developers.google.com/protocol-buffers/docs/encoding#structure
class WireType(Enum):
    VarInt = 0
    Bit64 = 1
    LengthDelimited = 2
    StartGroup = 3
    EndGroup = 4
    Bit32 = 5

    @classmethod
    def has_value(cls, value):
        for member in cls:
            if member.value == value:
                return True
        return False

    @classmethod
    def try_parse(cls, value) -> Union["WireType", None]:
        if WireType.has_value(value):
            return WireType(value)

        return None


class FieldDescriptorType(Enum):
    Double = FieldDescriptorProto.TYPE_DOUBLE
    Float = FieldDescriptorProto.TYPE_FLOAT
    Int64 = FieldDescriptorProto.TYPE_INT64
    UInt64 = FieldDescriptorProto.TYPE_UINT64
    Int32 = FieldDescriptorProto.TYPE_INT32
    Fixed64 = FieldDescriptorProto.TYPE_FIXED64
    Fixed32 = FieldDescriptorProto.TYPE_FIXED32
    Bool = FieldDescriptorProto.TYPE_BOOL
    String = FieldDescriptorProto.TYPE_STRING
    Group = FieldDescriptorProto.TYPE_GROUP
    Message = FieldDescriptorProto.TYPE_MESSAGE
    Bytes = FieldDescriptorProto.TYPE_BYTES
    UInt32 = FieldDescriptorProto.TYPE_UINT32
    Enum = FieldDescriptorProto.TYPE_ENUM
    SFixed32 = FieldDescriptorProto.TYPE_SFIXED32
    SFixed64 = FieldDescriptorProto.TYPE_SFIXED64
    SInt32 = FieldDescriptorProto.TYPE_SINT32
    SInt64 = FieldDescriptorProto.TYPE_SINT64

    _ignore_ = ['_values']
    _values = set()

    def to_str(self):
        return self.name.lower()

    @classmethod
    def has_value(cls, value):
        return value in FieldDescriptorType._values

    @classmethod
    def try_parse(cls, value) -> Union["FieldDescriptorType", None]:
        if value == 0:
            return None

        if FieldDescriptorType.has_value(value):
            return FieldDescriptorType(value)

        return None


# Cache enum values
FieldDescriptorType._values = set()
for data in FieldDescriptorType:
    FieldDescriptorType._values.add(data.value)


def left_pad(value: str, depth: int):
    return f"{'  ' * depth}{value}"


def is_valid_filename(filename):
    """
    Check if given filename may be valid
    """
    charset = b"abcdefghijklmnopqrstuvwxyz0123456789-_/$,.[]()"
    for char in filename.lower():
        if char not in charset:
            return False
    return True

# See: https://developers.google.com/protocol-buffers/docs/encoding#varints


def decode_varint128(stream: bytes) -> Tuple[int, int]:
    """
    Decode Varint128 from buffer
    """
    result = ""
    count = 0
    for byte in stream:
        count += 1

        lower_7_bits = byte & 0x7F
        # [2:] removes the '0b' created by bin()
        binary_repr = bin(lower_7_bits)[2:]
        padded = binary_repr.rjust(7, "0")

        result += padded
        if (byte & 0x80) != 0x80:
            break

    return (int(result, 2), count)


def render_type(field_type: str, package: str) -> str:
    """
    Return the string representing a given type inside a given package
    """
    field_parts = field_type.split(".")
    package_parts = package.split(".")

    i = 0
    while i < len(package_parts) and field_parts[i] == package_parts[i]:
        i += 1

    return ".".join(field_parts[i:])


def parse_file_descriptor_proto(buffer: bytes) -> Union[FileDescriptorProto, None]:
    try:
        descriptor = FileDescriptorProto()
        descriptor.ParseFromString(buffer)
        return descriptor
    except DecodeError:
        return None

#############################
# Protobuf fields walker
#############################


debug_count = 0


class ProtobufFieldsWalker:
    """
    Homemade Protobuf fields walker

    This class allows Protod to walk the fields
    and determine the probable size of the protobuf
    serialized file.
    """

    _stream: bytes
    _size: int

    def __init__(self, stream):
        self._stream = stream
        self._size = -1

    def get_size(self):
        return self._size

    def walk(self):
        d = False
        end = False
        offset = 0
        while (not end) and (offset < len(self._stream)):
            # read tag
            tag = self._stream[offset]
            offset += 1

            wire_type = WireType.try_parse(tag & 0x7)
            match wire_type:
                case WireType.VarInt:
                    value, size = decode_varint128(self._stream[offset:])
                    offset += size
                    if d:
                        print(f"VarInt({size})")
                case WireType.Bit64:
                    offset += 8
                    if d:
                        print("Bit64(8)")
                case WireType.LengthDelimited:
                    value, size = decode_varint128(self._stream[offset:])
                    offset += size + value
                    if d:
                        print(self._stream[(offset + size):(offset + size + value)])
                        print(f"LengthDelimited({size}, {value})")
                case WireType.Bit32:
                    offset += 4
                    if d:
                        print("Bit32(4)")
                case WireType.StartGroup:
                    continue
                case WireType.EndGroup:
                    continue
                case None:
                    # print("End")
                    end = True

        self._size = offset - 1
        # print(f"walk {{ size: {self._size}, offset: {offset} }}")

#############################
# Serialized metadata parsing
#############################


class FileDescriptorDisassembler:
    """
    Core disassembling class

    This class parses the provided serialized data and
    produces one or many .proto files.
    """

    descriptor: FileDescriptorProto

    def __init__(self, file_descriptor: FileDescriptorProto):
        self.descriptor = file_descriptor

    def get_label(self, l):
        return [None, "optional", "required", "repeated"][l]

    def get_type_str(self, type_id: int) -> str:
        return FieldDescriptorType.try_parse(type_id).to_str()

    def renderEnum(self, enum, depth=0, package="", nested=False):
        header = left_pad(f"enum {enum.name}", depth)
        values = "\n".join([left_pad(f"{x.name} = {x.number};", depth + 1) for x in enum.value])

        return f"{header} {{\n{values}\n}}\n\n"

    # def render_message(self, message: DescriptorProto):
    #     for field in message.fie

    def renderField(self, field: DescriptorProto, depth=0, package="", nested=False) -> str:
        if hasattr(field, "type"):
            label = self.get_label(field.label)

            match field.type:
                case FieldDescriptorProto.TYPE_MESSAGE | FieldDescriptorProto.TYPE_ENUM:
                    field.type_name = render_type(field.type_name[1:], package)
                    result = f"{label} {field.type_name} {field.name} = {field.number};\n"
                case _:
                    field_type = self.get_type_str(field.type)
                    result = f"{label} {field_type} {field.name} = {field.number}"

                    if field.HasField("default_value"):
                        if field_type == "string":
                            field.default_value = f'"{field.default_value}"'

                        result += f" [default = {field.default_value}]"

                    result += ";\n"

            return left_pad(result, depth)
        else:
            buffer = left_pad(f"message {field.name} {{\n", depth)

            next_package = f"{package}.{field.name}"
            next_depth = depth + 1

            if field.nested_type:
                for nested in field.nested_type:
                    buffer += self.renderField(nested, next_depth, next_package, nested=True)

            if field.enum_type:
                for enum in field.enum_type:
                    buffer += self.renderEnum(enum, next_depth, next_package)

            if field.field:
                for field in field.field:
                    buffer += self.renderField(field, next_depth, next_package)

            buffer += left_pad("}\n\n", depth)

            return buffer

    def render(self, filename=None):
        descriptor = self.descriptor
        # print(f"[+] Processing {descriptor.name}")
        buffer = f"package {descriptor.package};\n\n"

        # add dependencies
        if len(descriptor.dependency) > 0:
            for dependency in descriptor.dependency:
                buffer += f'import "{dependency}";\n'
            buffer += "\n"

        if len(descriptor.enum_type) > 0:
            for enum in descriptor.enum_type:
                buffer += self.renderEnum(enum, package=descriptor.package)

        if len(descriptor.message_type) > 0:
            messages: Sequence[DescriptorProto] = descriptor.message_type
            for message in messages:
                buffer += self.renderField(message, package=descriptor.package)

        if filename:
            _dir = os.path.dirname(filename)
            if _dir != "" and not os.path.exists(_dir):
                os.makedirs(_dir)
            open(filename, "w").write(buffer)
        else:
            _dir = os.path.dirname(descriptor.name)
            if _dir != "" and not os.path.exists(_dir):
                os.makedirs(_dir)
            open(descriptor.name, "w").write(buffer)


#############################
# Main code
#############################

global_dbg = False


class ProtobufExtractor:
    filename_predicate: Callable[[str], bool]

    def __init__(self, filename=None, filename_predicate=None):
        self.filename = filename
        self.filename_predicate = filename_predicate

    def _find_proto_descriptor(self, buffer: bytes, start: int, filename: str) -> Union[Tuple[FileDescriptorProto, bytes, int], None]:
        # Walk the fields and get a probable size
        walker = ProtobufFieldsWalker(buffer[start:])
        walker.walk()
        probable_size = walker.get_size()

        if self.filename_predicate and not(self.filename_predicate(filename)):
            print(
                f"[i] Skipping protofile {filename} (Reason: filtered out. Approximate size: {probable_size} bytes)")
            return None

        """
        Probable size approach is not perfect. We add a delta of 1024 bytes to be sure
        not to miss something
        """

        for k in range(probable_size + 1024, 0, -1):
            protoc_data = buffer[start:(start + k)]
            descriptor = parse_file_descriptor_proto(protoc_data)
            if descriptor:
                return descriptor, protoc_data, k

    def extract(self, byte_pattern=b".proto"):
        byte_pattern_length = len(byte_pattern)
        try:
            with open(self.filename, "rb") as file:
                stream: bytes = file.read()
                stream_size = len(stream)

                protos: list[Tuple[FileDescriptorProto, bytes]] = []
                cursor = 0

                while cursor < stream_size:
                    cursor = stream.find(byte_pattern, cursor)

                    # Break when there are no more matches
                    if cursor == -1:
                        break

                    for filename_length in range(64):
                        try:
                            value = decode_varint128(stream[cursor - filename_length:])[0]

                            potential_filename = substr_including(
                                stream[cursor - filename_length + 1: cursor + byte_pattern_length], b".proto")

                            if value == (filename_length + 5) and is_valid_filename(potential_filename):
                                filename = potential_filename.decode()

                                start = cursor - filename_length - 1
                                result = self._find_proto_descriptor(stream, start, filename)

                                if result:
                                    (descriptor, protoc_data, advanced_bytes) = result

                                    protos.append((descriptor, protoc_data))

                                    file_percentage = f"{(100 * (cursor / float(stream_size))):.2f}%"
                                    detail_info = f"byte {cursor:,}/{stream_size:,}, at {file_percentage} in the file"
                                    print(f"[i] Found protofile {filename} ({advanced_bytes} bytes) ({detail_info})")

                                    cursor += advanced_bytes
                                    break
                                break
                        except IndexError as e:
                            print("IndexError: ", e)
                            pass

                    cursor += byte_pattern_length

                # Load successively each binary proto file and rebuild it from scratch
                seen = []
                for (fileDescriptor, protoc_data) in protos:
                    try:
                        # Load the prototype
                        disassembler = FileDescriptorDisassembler(fileDescriptor)
                        filename = disassembler.descriptor.name
                        if len(filename) > 0:
                            basepath = "./"
                            path = os.path.join(basepath, filename)
                            os.makedirs(os.path.dirname(path), exist_ok=True)
                            if filename not in seen:
                                open(f"{filename}.protoc", "wb").write(protoc_data)
                                disassembler.render()
                                print(f"[i] Created {filename}")
                                seen.append(filename)

                    except DecodeError:
                        pass

        except IOError as e:
            print(f"[!] Unable to read file: '{sys.argv[1]}. Error:\n{e}'")


def filename_predicate(filename: str):
    return "google/protobuf" not in filename


def substr_including(value: Union[bytes, str], substring: Union[bytes, str]) -> Union[str, None]:
    i = value.find(substring)
    if i == -1:
        return None

    return value[:i + len(substring)]


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        print(f"[i] Extracting from {sys.argv[1]} ...")
        extractor = ProtobufExtractor(sys.argv[1], filename_predicate=filename_predicate)
        extractor.extract(byte_pattern=b".proto\x12")
        print("[i] Done")
    else:
        print("[ Protod (Protobuf metadata extractor) (c) 2012 Sysdream  ]")
        print("")
        print(f"[i] Usage: {sys.argv[0]} [executable]")
