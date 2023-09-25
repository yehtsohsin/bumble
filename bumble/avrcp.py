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
from typing import Callable, List, Optional, Tuple

from bumble.colors import color
from bumble.sdp import (
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
    SDP_PUBLIC_BROWSE_ROOT,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
    DataElement,
    ServiceAttribute,
)
from bumble.utils import OpenIntEnum
from bumble.core import (
    BT_L2CAP_PROTOCOL_ID,
    BT_AVCTP_PROTOCOL_ID,
    BT_AV_REMOTE_CONTROL_SERVICE,
    BT_AV_REMOTE_CONTROL_CONTROLLER_SERVICE,
    BT_AV_REMOTE_CONTROL_TARGET_SERVICE,
)
from bumble import l2cap
from bumble import avc
from bumble import avctp


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
AVRCP_PID = 0x110E
AVRCP_BLUETOOTH_SIG_COMPANY_ID = 0x001958


# -----------------------------------------------------------------------------
def make_controller_service_sdp_records(
    service_record_handle: int,
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
                    DataElement.uuid(BT_AV_REMOTE_CONTROL_CONTROLLER_SERVICE),
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
                            DataElement.unsigned_integer_16(avctp.AVCTP_PSM),
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
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_AV_REMOTE_CONTROL_SERVICE),
                            DataElement.unsigned_integer_16(avrcp_version_int),
                        ]
                    ),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
            DataElement.unsigned_integer_16(supported_features),
        ),
    ]


# -----------------------------------------------------------------------------
def make_target_service_sdp_records(
    service_record_handle: int,
    avctp_version: Tuple[int, int] = (1, 4),
    avrcp_version: Tuple[int, int] = (1, 6),
    supported_features: int = 0x23,
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
                    DataElement.uuid(BT_AV_REMOTE_CONTROL_TARGET_SERVICE),
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
                            DataElement.unsigned_integer_16(avctp.AVCTP_PSM),
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
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_AV_REMOTE_CONTROL_SERVICE),
                            DataElement.unsigned_integer_16(avrcp_version_int),
                        ]
                    ),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
            DataElement.unsigned_integer_16(supported_features),
        ),
    ]


# -----------------------------------------------------------------------------
class PduAssembler:
    """
    PDU Assembler to support fragmented PDUs are defined in:
    Audio/Video Remote Control / Profile Specification
    6.3.1 AVRCP specific AV//C commands
    """

    pdu_id: Optional[Protocol.PduId]
    payload: bytes

    def __init__(self, callback: Callable[[Protocol.PduId, bytes], None]) -> None:
        self.callback = callback
        self.reset()

    def reset(self) -> None:
        self.pdu_id = None
        self.parameter = b''

    def on_pdu(self, pdu: bytes) -> None:
        pdu_id = Protocol.PduId(pdu[0])
        packet_type = Protocol.PacketType(pdu[1] & 3)
        parameter_length = struct.unpack_from('>H', pdu, 2)[0]
        parameter = pdu[4 : 4 + parameter_length]
        if len(parameter) != parameter_length:
            logger.warning("parameter length exceeds pdu size")
            self.reset()
            return

        if packet_type in (Protocol.PacketType.SINGLE, Protocol.PacketType.START):
            if self.pdu_id is not None:
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

    class PduId(OpenIntEnum):
        GET_CAPABILITIES = 0x10

    command_type: Optional[avc.CommandFrame.CommandType]
    command_pdu_assembler: PduAssembler
    response_code: Optional[avc.ResponseFrame.ResponseCode]
    response_pdu_assembler: PduAssembler
    avctp_protocol: avctp.Protocol

    @staticmethod
    def check_vendor_dependent_frame(frame: avc.VendorDependentFrame) -> bool:
        if frame.company_id != AVRCP_BLUETOOTH_SIG_COMPANY_ID:
            logger.debug("unsupported company id, ignoring")
            return False

        if frame.subunit_type != avc.Frame.SubunitType.PANEL or frame.subunit_id != 0:
            logger.debug("unsupported subunit")
            return False

        return True

    def __init__(self, l2cap_channel: l2cap.Channel) -> None:
        self.command_type = None
        self.command_pdu_assembler = PduAssembler(self.on_command_pdu)
        self.response_code = None
        self.response_pdu_assembler = PduAssembler(self.on_response_pdu)

        self.avctp_protocol = avctp.Protocol(l2cap_channel)
        self.avctp_protocol.register_command_handler(AVRCP_PID, self.on_avctp_command)
        self.avctp_protocol.register_response_handler(AVRCP_PID, self.on_avctp_response)

    def on_avctp_command(
        self, transaction_label: int, command: avc.CommandFrame
    ) -> None:
        logger.debug(
            f">>> AVCTP Command, transaction_label={transaction_label}: " f"{command}"
        )

        # Only the PANEL subunit type with subunit ID 0 is supported in this profile.
        if (
            command.subunit_type != avc.Frame.SubunitType.PANEL
            or command.subunit_id != 0
        ):
            logger.debug("subunit not supported")
            self.send_not_implemented_response(transaction_label, command.opcode)
            return

        if isinstance(command, avc.VendorDependentCommandFrame):
            if not self.check_vendor_dependent_frame(command):
                return

            if self.command_type is not None:
                # We're in the middle of some other PDU
                logger.warning("received interleaved PDU, resetting state")
                self.command_pdu_assembler.reset()
                self.command_type = None
                return

            self.command_pdu_assembler.on_pdu(command.vendor_dependent_data)
            return

        # TODO handle other types
        self.send_not_implemented_response(transaction_label, command.opcode)

    def on_avctp_response(
        self, transaction_label: int, response: avc.ResponseFrame
    ) -> None:
        logger.debug(
            f">>> AVCTP Response, transaction_label={transaction_label}: {response}"
        )

        if isinstance(response, avc.VendorDependentResponseFrame):
            if not self.check_vendor_dependent_frame(response):
                return

            if self.response_code is not None:
                # We're in the middle of some other PDU
                logger.warning("received interleaved PDU, resetting state")
                self.response_pdu_assembler.reset()
                self.response_code = None
                return

            self.response_pdu_assembler.on_pdu(response.vendor_dependent_data)
            return

        # TODO handle other types

    def on_command_pdu(self, pdu_id: PduId, pdu: bytes) -> None:
        logger.debug(f"AVRCP command PDU [pdu_id={pdu_id.name}]: {pdu.hex()}")
        self.command_type = None

    def on_response_pdu(self, pdu_id: PduId, pdu: bytes) -> None:
        logger.debug(f"AVRCP response PDU [pdu_id={pdu_id.name}]: {pdu.hex()}")
        self.response_code = None

    def send_response(self, transaction_label: int, response: avc.ResponseFrame):
        self.avctp_protocol.send_response(transaction_label, AVRCP_PID, bytes(response))

    def send_not_implemented_response(
        self, transaction_label: int, opcode: avc.Frame.OperationCode
    ) -> None:
        response = avc.ResponseFrame(
            avc.ResponseFrame.ResponseCode.NOT_IMPLEMENTED,
            avc.Frame.SubunitType.PANEL,
            0,
            opcode,
            b'',
        )
        self.send_response(transaction_label, response)
