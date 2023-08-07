# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import pytest
import struct

from bumble import avc
from bumble import avrcp
from bumble import avctp


# -----------------------------------------------------------------------------
def test_frame_parser():
    with pytest.raises(ValueError) as error:
        avc.Frame.from_bytes(bytes.fromhex("11480000"))

    x = bytes.fromhex("014D0208")
    frame = avc.Frame.from_bytes(x)
    assert frame.subunit_type == avc.Frame.SubunitType.PANEL
    assert frame.subunit_id == 7
    assert frame.opcode == 8

    x = bytes.fromhex("014DFF0108")
    frame = avc.Frame.from_bytes(x)
    assert frame.subunit_type == avc.Frame.SubunitType.PANEL
    assert frame.subunit_id == 260
    assert frame.opcode == 8

    x = bytes.fromhex("0148000019581000000103")

    frame = avc.Frame.from_bytes(x)

    assert isinstance(frame, avc.CommandFrame)
    assert frame.ctype == avc.CommandFrame.CommandType.STATUS
    assert frame.subunit_type == avc.Frame.SubunitType.PANEL
    assert frame.subunit_id == 0
    assert frame.opcode == 0


# -----------------------------------------------------------------------------
def test_vendor_dependent_command():
    x = bytes.fromhex("0148000019581000000103")
    frame = avc.Frame.from_bytes(x)
    assert isinstance(frame, avc.VendorDependentCommandFrame)
    assert frame.company_id == 0x1958
    assert frame.vendor_dependent_data == bytes.fromhex("1000000103")

    frame = avc.VendorDependentCommandFrame(
        avc.CommandFrame.CommandType.STATUS,
        avc.Frame.SubunitType.PANEL,
        0,
        0x1958,
        bytes.fromhex("1000000103"),
    )
    assert bytes(frame) == x


# -----------------------------------------------------------------------------
def test_avctp_message_assembler():
    received_message = []

    def on_message(transaction_label, is_response, ipid, pid, payload):
        received_message.append((transaction_label, is_response, ipid, pid, payload))

    assembler = avctp.MessageAssembler(on_message)

    payload = bytes.fromhex("01")
    assembler.on_pdu(bytes([1 << 4 | 0b00 << 2 | 1 << 1 | 0, 0x11, 0x22]) + payload)
    assert received_message
    assert received_message[0] == (1, False, False, 0x1122, payload)

    received_message = []
    payload = bytes.fromhex("010203")
    assembler.on_pdu(bytes([1 << 4 | 0b01 << 2 | 1 << 1 | 0, 0x11, 0x22]) + payload)
    assert len(received_message) == 0
    assembler.on_pdu(bytes([1 << 4 | 0b00 << 2 | 1 << 1 | 0, 0x11, 0x22]) + payload)
    assert received_message
    assert received_message[0] == (1, False, False, 0x1122, payload)

    received_message = []
    payload = bytes.fromhex("010203")
    assembler.on_pdu(
        bytes([1 << 4 | 0b01 << 2 | 1 << 1 | 0, 3, 0x11, 0x22]) + payload[0:1]
    )
    assembler.on_pdu(
        bytes([1 << 4 | 0b10 << 2 | 1 << 1 | 0, 0x11, 0x22]) + payload[1:2]
    )
    assembler.on_pdu(
        bytes([1 << 4 | 0b11 << 2 | 1 << 1 | 0, 0x11, 0x22]) + payload[2:3]
    )
    assert received_message
    assert received_message[0] == (1, False, False, 0x1122, payload)

    # received_message = []
    # parameter = bytes.fromhex("010203")
    # assembler.on_pdu(struct.pack(">BBH", 0x10, 0b11, len(parameter)) + parameter)
    # assert len(received_message) == 0


# -----------------------------------------------------------------------------
def test_avrcp_pdu_assembler():
    received_pdus = []

    def on_pdu(pdu_id, parameter):
        received_pdus.append((pdu_id, parameter))

    assembler = avrcp.PduAssembler(on_pdu)

    parameter = bytes.fromhex("01")
    assembler.on_pdu(struct.pack(">BBH", 0x10, 0b00, len(parameter)) + parameter)
    assert received_pdus
    assert received_pdus[0] == (0x10, parameter)

    received_pdus = []
    parameter = bytes.fromhex("010203")
    assembler.on_pdu(struct.pack(">BBH", 0x10, 0b01, len(parameter)) + parameter)
    assert len(received_pdus) == 0
    assembler.on_pdu(struct.pack(">BBH", 0x10, 0b00, len(parameter)) + parameter)
    assert received_pdus
    assert received_pdus[0] == (0x10, parameter)

    received_pdus = []
    parameter = bytes.fromhex("010203")
    assembler.on_pdu(struct.pack(">BBH", 0x10, 0b01, 1) + parameter[0:1])
    assembler.on_pdu(struct.pack(">BBH", 0x10, 0b10, 1) + parameter[1:2])
    assembler.on_pdu(struct.pack(">BBH", 0x10, 0b11, 1) + parameter[2:3])
    assert received_pdus
    assert received_pdus[0] == (0x10, parameter)

    received_pdus = []
    parameter = bytes.fromhex("010203")
    assembler.on_pdu(struct.pack(">BBH", 0x10, 0b11, len(parameter)) + parameter)
    assert len(received_pdus) == 0


def test_passthrough_commands():
    play_pressed = avc.PassThroughCommandFrame(
        avc.CommandFrame.CommandType.CONTROL,
        avc.CommandFrame.SubunitType.PANEL,
        0,
        avc.PassThroughCommandFrame.StateFlag.PRESSED,
        avc.PassThroughCommandFrame.OperationId.PLAY,
        b'',
    )

    play_pressed_bytes = bytes(play_pressed)
    parsed = avc.Frame.from_bytes(play_pressed_bytes)
    assert isinstance(parsed, avc.PassThroughCommandFrame)
    assert parsed.operation_id == avc.PassThroughCommandFrame.OperationId.PLAY
    assert bytes(parsed) == play_pressed_bytes


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_frame_parser()
    test_vendor_dependent_command()
    test_avctp_message_assembler()
    test_avrcp_pdu_assembler()
    test_passthrough_commands()
