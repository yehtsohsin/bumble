# Copyright 2021-2023 Google LLC
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
from __future__ import annotations
import enum
import logging
import struct
from typing import Callable, List, Tuple

from bumble.colors import color
from bumble.sdp import (
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
    SDP_PUBLIC_BROWSE_ROOT,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_ADDITIONAL_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
    DataElement,
    ServiceAttribute,
)
from bumble.core import (
    UUID,
    BT_L2CAP_PROTOCOL_ID,
    BT_AVCTP_PROTOCOL_ID,
    BT_AV_REMOTE_CONTROL_SERVICE,
    BT_AV_REMOTE_CONTROL_CONTROLLER_SERVICE,
    BT_AV_REMOTE_CONTROL_TARGET_SERVICE,
)
from bumble.avctp import AVCTP_PSM, AVCTP_BROWSING_PSM


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
AVRCP_PID = 0x110E


# -----------------------------------------------------------------------------
def make_common_sdp_records(
    service_record_handle: int,
    service_class_uuid: UUID,
    avctp_version: Tuple[int, int] = (1, 4),
    avrcp_version: Tuple[int, int] = (1, 6),
    supported_features: int = 1,
) -> List[ServiceAttribute]:
    # TODO: support a way to compute the supported features from a feature list
    avctp_version_int = avctp_version[0] << 8 | avctp_version[1]
    avrcp_version_int = avrcp_version[0] << 8 | avrcp_version[1]

    return [
        ServiceAttribute(
            SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
            DataElement.unsigned_integer_32(service_record_handle),
        ),
        ServiceAttribute(
            SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
            DataElement.sequence([DataElement.uuid(SDP_PUBLIC_BROWSE_ROOT)]),
        ),
        ServiceAttribute(
            SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.uuid(BT_AV_REMOTE_CONTROL_SERVICE),
                    DataElement.uuid(service_class_uuid),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_L2CAP_PROTOCOL_ID),
                            DataElement.unsigned_integer_16(AVCTP_PSM),
                        ]
                    ),
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_AVCTP_PROTOCOL_ID),
                            DataElement.unsigned_integer_16(avctp_version_int),
                        ]
                    ),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.uuid(BT_AV_REMOTE_CONTROL_SERVICE),
                    DataElement.unsigned_integer_16(avrcp_version_int),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
            DataElement.unsigned_integer_16(supported_features),
        ),
    ]


# -----------------------------------------------------------------------------
def make_controller_service_sdp_records(
    service_record_handle: int,
    avctp_version: Tuple[int, int] = (1, 4),
    avrcp_version: Tuple[int, int] = (1, 6),
    supported_features: int = 1,
) -> List[ServiceAttribute]:
    return make_common_sdp_records(
        service_record_handle,
        BT_AV_REMOTE_CONTROL_CONTROLLER_SERVICE,
        avctp_version,
        avrcp_version,
        supported_features,
    )


# -----------------------------------------------------------------------------
def make_target_service_sdp_records(
    service_record_handle: int,
    avctp_version: Tuple[int, int] = (1, 4),
    avrcp_version: Tuple[int, int] = (1, 6),
    supported_features: int = 1,
) -> List[ServiceAttribute]:
    avctp_version_int = avctp_version[0] << 8 | avctp_version[1]
    common_sdp_records = make_common_sdp_records(
        service_record_handle,
        BT_AV_REMOTE_CONTROL_TARGET_SERVICE,
        avctp_version,
        avrcp_version,
        supported_features,
    )
    additional_protocol_descriptors = [
        ServiceAttribute(
            SDP_ADDITIONAL_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_L2CAP_PROTOCOL_ID),
                            DataElement.unsigned_integer_16(AVCTP_BROWSING_PSM),
                        ]
                    ),
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_AVCTP_PROTOCOL_ID),
                            DataElement.unsigned_integer_16(avctp_version_int),
                        ]
                    ),
                ]
            ),
        ),
    ]
    return (
        common_sdp_records[:3]
        + additional_protocol_descriptors
        + common_sdp_records[3:]
    )


# SERVICE:
#   Attribute(id=SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,value=UNSIGNED_INTEGER(65542#4))
#   Attribute(id=SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,value=SEQUENCE([UUID(UUID-16:110E (A/V_RemoteControl)),UUID(UUID-16:110F (A/V_RemoteControlController))]))
#   Attribute(id=SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,value=SEQUENCE([SEQUENCE([UUID(UUID-16:0100 (L2CAP)),UNSIGNED_INTEGER(23#2)]),SEQUENCE([UUID(UUID-16:0017 (AVCTP)),UNSIGNED_INTEGER(260#2)])]))
#   Attribute(id=SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,value=SEQUENCE([SEQUENCE([UUID(UUID-16:110E (A/V_RemoteControl)),UNSIGNED_INTEGER(262#2)])]))
#   Attribute(id=[0x311],value=UNSIGNED_INTEGER(1#2))
# SERVICE:
#   Attribute(id=SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,value=UNSIGNED_INTEGER(65544#4))
#   Attribute(id=SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,value=SEQUENCE([UUID(UUID-16:110C (A/V_RemoteControlTarget))]))
#   Attribute(id=SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,           value=SEQUENCE([SEQUENCE([UUID(UUID-16:0100 (L2CAP)),UNSIGNED_INTEGER(23#2)]),SEQUENCE([UUID(UUID-16:0017 (AVCTP)),UNSIGNED_INTEGER(260#2)])]))
#   Attribute(id=SDP_ADDITIONAL_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,value=SEQUENCE([SEQUENCE([UUID(UUID-16:0100 (L2CAP)),UNSIGNED_INTEGER(27#2)]),SEQUENCE([UUID(UUID-16:0017 (AVCTP)),UNSIGNED_INTEGER(260#2)])]))
#   Attribute(id=SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,value=SEQUENCE([SEQUENCE([UUID(UUID-16:110E (A/V_RemoteControl)),UNSIGNED_INTEGER(262#2)])]))
#   Attribute(id=[0x311],value=UNSIGNED_INTEGER(35#2))


# -----------------------------------------------------------------------------
class PduAssembler:
    """
    PDU Assembler to support fragmented PDUs are defined in:
    Audio/Video Remote Control / Profile Specification
    6.3.1 AVRCP specific AV//C commands
    """

    Callback = Callable[[int, bytes], None]
    pdu_id: int
    payload: bytes

    def __init__(self, callback: Callback) -> None:
        self.callback = callback
        self.reset()

    def reset(self) -> None:
        self.pdu_id = -1
        self.parameter = b''

    def on_pdu(self, pdu: bytes) -> None:
        pdu_id = pdu[0]
        packet_type = Protocol.PacketType(pdu[1] & 3)
        parameter_length = struct.unpack_from('>H', pdu, 2)[0]
        parameter = pdu[4 : 4 + parameter_length]
        if len(parameter) != parameter_length:
            logger.warning("parameter length exceeds pdu size")
            self.reset()
            return

        if packet_type in (Protocol.PacketType.SINGLE, Protocol.PacketType.START):
            if self.pdu_id >= 0:
                # We are already in a PDU
                logger.warning("received START or SINGLE fragment while in pdu")
                self.reset()

        if packet_type in (Protocol.PacketType.CONTINUE, Protocol.PacketType.END):
            if pdu_id != self.pdu_id:
                logger.warning("PID does not match")
                self.reset()
                return
        else:
            self.pdu_id = pdu_id

        self.parameter += parameter

        if packet_type in (Protocol.PacketType.SINGLE, Protocol.PacketType.END):
            self.on_pdu_complete()

    def on_pdu_complete(self) -> None:
        try:
            self.callback(self.pdu_id, self.parameter)
        except Exception as error:
            logger.warning(color(f'!!! exception in callback: {error}'))

        self.reset()


# -----------------------------------------------------------------------------
class Protocol:
    class PacketType(enum.IntEnum):
        SINGLE = 0b00
        START = 0b01
        CONTINUE = 0b10
        END = 0b11

    def __init__(self) -> None:
        self.pdu_assembler = PduAssembler(self.on_pdu)

    def on_pdu(self, pdu_id: int, parameter: bytes):
        print("===", pdu_id, parameter.hex())
