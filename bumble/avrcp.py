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
from dataclasses import dataclass
import enum
import logging
import struct
from typing import Callable, Dict, Iterable, List, Optional, SupportsBytes, Tuple

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
@dataclass
class Command:
    pdu_id: Protocol.PduId
    parameter: bytes

    def to_string(self, properties: Dict[str, str]) -> str:
        properties_str = ",".join(
            [f"{name}={value}" for name, value in properties.items()]
        )
        return f"Command[{self.pdu_id.name}]({properties_str})"

    def __str__(self) -> str:
        return self.to_string({"parameters": self.parameter.hex()})


# -----------------------------------------------------------------------------
class GetCapabilitiesCommand(Command):
    class CapabilityId(OpenIntEnum):
        COMPANY_ID = 0x02
        EVENTS_SUPPORTED = 0x03

    capability_id: CapabilityId

    @classmethod
    def from_bytes(cls, pdu: bytes) -> GetCapabilitiesCommand:
        return cls(cls.CapabilityId(pdu[0]))

    def __init__(self, capability_id: CapabilityId) -> None:
        super().__init__(Protocol.PduId.GET_CAPABILITIES, bytes([capability_id]))
        self.capability_id = capability_id

    def __str__(self) -> str:
        return self.to_string({"capability_id": self.capability_id.name})


# -----------------------------------------------------------------------------
class SetAbsoluteVolumeCommand(Command):
    MAXIMUM_VOLUME = 0x7F

    volume: int

    @classmethod
    def from_bytes(cls, pdu: bytes) -> SetAbsoluteVolumeCommand:
        return cls(pdu[0])

    def __init__(self, volume: int) -> None:
        super().__init__(Protocol.PduId.SET_ABSOLUTE_VOLUME, bytes([volume]))
        self.volume = volume

    def __str__(self) -> str:
        return self.to_string({"volume": str(self.volume)})


# -----------------------------------------------------------------------------
class RegisterNotificationCommand(Command):
    event_id: EventId
    playback_interval: int

    @classmethod
    def from_bytes(cls, pdu: bytes) -> RegisterNotificationCommand:
        event_id = EventId(pdu[0])
        playback_interval = struct.unpack_from(">I", pdu, 1)[0]
        return cls(event_id, playback_interval)

    def __init__(self, event_id: EventId, playback_interval: int) -> None:
        super().__init__(
            Protocol.PduId.REGISTER_NOTIFICATION,
            struct.pack(">BI", int(event_id), playback_interval),
        )
        self.event_id = event_id
        self.playback_interval = playback_interval

    def __str__(self) -> str:
        return self.to_string(
            {
                "event_id": self.event_id.name,
                "playback_interval": str(self.playback_interval),
            }
        )


# -----------------------------------------------------------------------------
@dataclass
class Response:
    pdu_id: Protocol.PduId
    parameter: bytes

    def to_string(self, properties: Dict[str, str]) -> str:
        properties_str = ",".join(
            [f"{name}={value}" for name, value in properties.items()]
        )
        return f"Response[{self.pdu_id.name}]({properties_str})"

    def __str__(self) -> str:
        return self.to_string({"parameters": self.parameter.hex()})


# -----------------------------------------------------------------------------
class RejectedResponse(Response):
    status_code: Protocol.StatusCode

    @classmethod
    def from_bytes(cls, pdu_id: Protocol.PduId, pdu: bytes) -> RejectedResponse:
        return cls(pdu_id, Protocol.StatusCode(pdu[0]))

    def __init__(
        self, pdu_id: Protocol.PduId, status_code: Protocol.StatusCode
    ) -> None:
        super().__init__(pdu_id, bytes([int(status_code)]))
        self.status_code = status_code

    def __str__(self) -> str:
        return self.to_string(
            {
                "status_code": self.status_code.name,
            }
        )


# -----------------------------------------------------------------------------
class GetCapabilitiesResponse(Response):
    capability_id: GetCapabilitiesCommand.CapabilityId
    capabilities: List[SupportsBytes]

    @classmethod
    def from_bytes(cls, pdu: bytes) -> GetCapabilitiesResponse:
        if len(pdu) < 2:
            # Possibly a reject response.
            return cls(GetCapabilitiesCommand.CapabilityId(0), [])

        # Assume that the payloads all follow the same pattern:
        #  <CapabilityID><CapabilityCount><Capability*>
        capability_id = GetCapabilitiesCommand.CapabilityId(pdu[0])
        capability_count = pdu[1]

        if capability_id == GetCapabilitiesCommand.CapabilityId.EVENTS_SUPPORTED:
            capabilities = [EventId(pdu[x]) for x in range(capability_count)]
        else:
            capability_size = (len(pdu) - 2) // capability_count
            capabilities = [
                pdu[x : x + capability_size]
                for x in range(2, len(pdu), capability_size)
            ]

        return cls(capability_id, capabilities)

    def __init__(
        self,
        capability_id: GetCapabilitiesCommand.CapabilityId,
        capabilities: List[SupportsBytes],
    ) -> None:
        super().__init__(
            Protocol.PduId.GET_CAPABILITIES,
            bytes([capability_id, len(capabilities)])
            + b''.join(bytes(capability) for capability in capabilities),
        )
        self.capability_id = capability_id
        self.capabilities = capabilities

    def __str__(self) -> str:
        return self.to_string(
            {
                "capability_id": self.capability_id.name,
                "capabilities": str(self.capabilities),
            }
        )


# -----------------------------------------------------------------------------
class SetAbsoluteVolumeResponse(Response):
    volume: int

    @classmethod
    def from_bytes(cls, pdu: bytes) -> SetAbsoluteVolumeResponse:
        return cls(pdu[0])

    def __init__(self, volume: int) -> None:
        super().__init__(Protocol.PduId.SET_ABSOLUTE_VOLUME, bytes([volume]))
        self.volume = volume

    def __str__(self) -> str:
        return self.to_string({"volume": str(self.volume)})


# -----------------------------------------------------------------------------
class RegisterNotificationResponse(Response):
    event_id: EventId
    payload: bytes

    @classmethod
    def from_bytes(cls, pdu: bytes) -> RegisterNotificationResponse:
        event_id = EventId(pdu[0])
        payload = pdu[1:]
        return cls(event_id, payload)

    def __init__(self, event_id: EventId, payload: bytes) -> None:
        super().__init__(
            Protocol.PduId.REGISTER_NOTIFICATION,
            bytes([int(event_id)]) + payload,
        )
        self.event_id = event_id
        self.payload = payload

    def __str__(self) -> str:
        return self.to_string(
            {
                "event_id": self.event_id.name,
                "payload": self.payload.hex(),
            }
        )


# -----------------------------------------------------------------------------
class EventId(OpenIntEnum):
    PLAYBACK_STATUS_CHANGED = 0x01
    TRACK_CHANGED = 0x02
    TRACK_REACHED_END = 0x03
    TRACK_REACHED_START = 0x04
    PLAYBACK_POS_CHANGED = 0x05
    BATT_STATUS_CHANGED = 0x06
    SYSTEM_STATUS_CHANGED = 0x07
    PLAYER_APPLICATION_SETTING_CHANGED = 0x08
    NOW_PLAYING_CONTENT_CHANGED = 0x09
    AVAILABLE_PLAYERS_CHANGED = 0x0A
    ADDRESSED_PLAYER_CHANGED = 0x0B
    UIDS_CHANGED = 0x0C
    VOLUME_CHANGED = 0x0D

    def __bytes__(self) -> bytes:
        return bytes([int(self)])


# -----------------------------------------------------------------------------
class Protocol:
    class PacketType(enum.IntEnum):
        SINGLE = 0b00
        START = 0b01
        CONTINUE = 0b10
        END = 0b11

    class PduId(OpenIntEnum):
        GET_CAPABILITIES = 0x10
        GET_ELEMENT_ATTRIBUTES = 0x20
        GET_PLAY_STATUS = 0x30
        REGISTER_NOTIFICATION = 0x31
        SET_ABSOLUTE_VOLUME = 0x50

    class StatusCode(OpenIntEnum):
        INVALID_COMMAND = 0x00
        INVALID_PARAMETER = 0x01
        PARAMETER_CONTENT_ERROR = 0x02
        INTERNAL_ERROR = 0x03
        OPERATION_COMPLETED = 0x04
        UID_CHANGED = 0x05
        INVALID_DIRECTION = 0x07
        NOT_A_DIRECTORY = 0x08
        DOES_NOT_EXIST = 0x09
        INVALID_SCOPE = 0x0A
        RANGE_OUT_OF_BOUNDS = 0x0B
        FOLDER_ITEM_IS_NOT_PLAYABLE = 0x0C
        MEDIA_IN_USE = 0x0D
        NOW_PLAYING_LIST_FULL = 0x0E
        SEARCH_NOT_SUPPORTED = 0x0F
        SEARCH_IN_PROGRESS = 0x10
        INVALID_PLAYER_ID = 0x11
        PLAYER_NOT_BROWSABLE = 0x12
        PLAYER_NOT_ADDRESSED = 0x13
        NO_VALID_SEARCH_RESULTS = 0x14
        NO_AVAILABLE_PLAYERS = 0x15
        ADDRESSED_PLAYER_CHANGED = 0x16

    @dataclass
    class ReceiveCommandState:
        transaction_label: int
        command_type: avc.CommandFrame.CommandType

    @dataclass
    class ReceiveResponseState:
        transaction_label: int
        response_code: avc.ResponseFrame.ResponseCode

    send_transaction_label: int
    command_pdu_assembler: PduAssembler
    receive_command_state: Optional[ReceiveCommandState]
    response_pdu_assembler: PduAssembler
    receive_response_state: Optional[ReceiveResponseState]
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
        self.send_transaction_label = 0
        self.command_pdu_assembler = PduAssembler(self.on_command_pdu)
        self.receive_command_state = None
        self.response_pdu_assembler = PduAssembler(self.on_response_pdu)
        self.receive_response_state = None

        self.avctp_protocol = avctp.Protocol(l2cap_channel)
        self.avctp_protocol.register_command_handler(AVRCP_PID, self.on_avctp_command)
        self.avctp_protocol.register_response_handler(AVRCP_PID, self.on_avctp_response)

        # TODO: testing
        @l2cap_channel.on("open")
        def on_l2cap_channel_open():
            self.send_command_pdu(
                avc.CommandFrame.CommandType.STATUS,
                GetCapabilitiesCommand(
                    GetCapabilitiesCommand.CapabilityId.EVENTS_SUPPORTED
                ),
            )
            self.send_command_pdu(
                avc.CommandFrame.CommandType.STATUS,
                GetCapabilitiesCommand(GetCapabilitiesCommand.CapabilityId.COMPANY_ID),
            )
            # self.send_command_pdu(
            #     avc.CommandFrame.CommandType.STATUS,
            #     GetCapabilitiesCommand(GetCapabilitiesCommand.CapabilityId(123)),
            # )

            for event_id in (
                EventId.TRACK_REACHED_END,
                EventId.SYSTEM_STATUS_CHANGED,
                EventId.PLAYBACK_STATUS_CHANGED,
                EventId.TRACK_CHANGED,
                EventId.PLAYER_APPLICATION_SETTING_CHANGED,
                EventId.NOW_PLAYING_CONTENT_CHANGED,
                EventId.AVAILABLE_PLAYERS_CHANGED,
                EventId(111),
            ):
                self.send_command_pdu(
                    avc.CommandFrame.CommandType.NOTIFY,
                    RegisterNotificationCommand(event_id, 0),
                )

    def on_avctp_command(
        self, transaction_label: int, command: avc.CommandFrame
    ) -> None:
        logger.debug(
            f"<<< AVCTP Command, transaction_label={transaction_label}: " f"{command}"
        )

        # Only the PANEL subunit type with subunit ID 0 is supported in this profile.
        if (
            command.subunit_type != avc.Frame.SubunitType.PANEL
            or command.subunit_id != 0
        ):
            logger.debug("subunit not supported")
            self.send_not_implemented_response(transaction_label, command)
            return

        if isinstance(command, avc.VendorDependentCommandFrame):
            if not self.check_vendor_dependent_frame(command):
                return

            if self.receive_command_state is None:
                self.receive_command_state = self.ReceiveCommandState(
                    transaction_label=transaction_label, command_type=command.ctype
                )
            elif (
                self.receive_command_state.transaction_label != transaction_label
                or self.receive_command_state.command_type != command.ctype
            ):
                # We're in the middle of some other PDU
                logger.warning("received interleaved PDU, resetting state")
                self.command_pdu_assembler.reset()
                self.receive_command_state = None
                return
            else:
                self.receive_command_state.command_type = command.ctype
                self.receive_command_state.transaction_label = transaction_label

            self.command_pdu_assembler.on_pdu(command.vendor_dependent_data)
            return

        if isinstance(command, avc.PassThroughCommandFrame):
            return

        # TODO handle other types
        self.send_not_implemented_response(transaction_label, command)

    def on_avctp_response(
        self, transaction_label: int, response: avc.ResponseFrame
    ) -> None:
        logger.debug(
            f"<<< AVCTP Response, transaction_label={transaction_label}: {response}"
        )

        if isinstance(response, avc.VendorDependentResponseFrame):
            if not self.check_vendor_dependent_frame(response):
                return

            if self.receive_response_state is None:
                self.receive_response_state = self.ReceiveResponseState(
                    transaction_label=transaction_label, response_code=response.response
                )
            elif (
                self.receive_response_state.transaction_label != transaction_label
                or self.receive_response_state.response_code != response.response
            ):
                # We're in the middle of some other PDU
                logger.warning("received interleaved PDU, resetting state")
                self.response_pdu_assembler.reset()
                self.receive_response_state = None
                return
            else:
                self.receive_response_state.response_code = response.response
                self.receive_response_state.transaction_label = transaction_label

            self.response_pdu_assembler.on_pdu(response.vendor_dependent_data)
            return

        # TODO handle other types

    def on_command_pdu(self, pdu_id: PduId, pdu: bytes) -> None:
        logger.debug(f"<<< AVRCP command PDU [pdu_id={pdu_id.name}]: {pdu.hex()}")

        # Dispatch the command.
        # NOTE: with a small number of supported commands, a manual dispatch like this
        # is Ok, but if/when more commands are supported, a lookup dispatch mechanism
        # would be more appropriate.
        # TODO: switch on ctype
        if self.receive_command_state.command_type in (
            avc.CommandFrame.CommandType.CONTROL,
            avc.CommandFrame.CommandType.STATUS,
            avc.CommandFrame.CommandType.NOTIFY,
        ):
            if pdu_id == self.PduId.GET_CAPABILITIES:
                self.on_get_capabilities_command(GetCapabilitiesCommand.from_bytes(pdu))
            elif pdu_id == self.PduId.SET_ABSOLUTE_VOLUME:
                self.on_set_absolute_volume_command(
                    SetAbsoluteVolumeCommand.from_bytes(pdu)
                )
            elif pdu_id == self.PduId.REGISTER_NOTIFICATION:
                self.on_register_notification_command(
                    RegisterNotificationCommand.from_bytes(pdu)
                )
            else:
                # Not supported.
                # TODO: check that this is the right way to respond in this case.
                logger.debug("unsupported PDU ID")
                self.send_rejected_response_pdu(self.StatusCode.INVALID_PARAMETER)
        else:
            logger.debug("unsupported command type")
            self.send_rejected_response_pdu(self.StatusCode.INVALID_COMMAND)

        self.receive_command_state = None

    def on_response_pdu(self, pdu_id: PduId, pdu: bytes) -> None:
        logger.debug(f"<<< AVRCP response PDU [pdu_id={pdu_id.name}]: {pdu.hex()}")

        # Convert the PDU bytes into an object.
        # NOTE: with a small number of supported responses, a manual switch like this
        # is Ok, but if/when more responses are supported, a lookup mechanism would be
        # more appropriate.
        if (
            self.receive_response_state.response_code
            == avc.ResponseFrame.ResponseCode.REJECTED
        ):
            pdu_object = RejectedResponse.from_bytes(pdu_id, pdu)
        elif self.receive_response_state.response_code in (
            avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE,
            avc.ResponseFrame.ResponseCode.INTERIM,
            avc.ResponseFrame.ResponseCode.CHANGED,
            avc.ResponseFrame.ResponseCode.ACCEPTED,
        ):
            if pdu_id == self.PduId.GET_CAPABILITIES:
                pdu_object = GetCapabilitiesResponse.from_bytes(pdu)
            elif pdu_id == self.PduId.SET_ABSOLUTE_VOLUME:
                pdu_object = SetAbsoluteVolumeResponse.from_bytes(pdu)
            else:
                logger.debug("unsupported PDU ID")
                pdu_object = None
        else:
            logger.debug("unsupported response code")
            pdu_object = None

        self.receive_response_state = None
        if pdu_object is None:
            return

        logger.debug(f"<<< AVRCP response PDU: {pdu_object}")


    def send_command(self, command: avc.CommandFrame) -> None:
        logger.debug(f">>> AVRCP command: {command}")

        self.avctp_protocol.send_command(
            self.send_transaction_label, AVRCP_PID, bytes(command)
        )
        # TODO: wait for response
        # TODO: increment transaction label
        self.send_transaction_label += 1

    def send_command_pdu(
        self, command_type: avc.CommandFrame.CommandType, command: Command
    ) -> None:
        # TODO: fragmentation
        logger.debug(f">>> AVRCP command PDU: {command}")
        pdu = (
            struct.pack(">BBH", command.pdu_id, 0, len(command.parameter))
            + command.parameter
        )
        command_frame = avc.VendorDependentCommandFrame(
            command_type,
            avc.Frame.SubunitType.PANEL,
            0,
            AVRCP_BLUETOOTH_SIG_COMPANY_ID,
            pdu,
        )
        self.send_command(command_frame)

    def send_response(
        self, transaction_label: int, response: avc.ResponseFrame
    ) -> None:
        logger.debug(f">>> AVRCP response: {response}")
        self.avctp_protocol.send_response(transaction_label, AVRCP_PID, bytes(response))

    def send_response_pdu(
        self, response_code: avc.ResponseFrame.ResponseCode, response: Response
    ) -> None:
        # TODO: fragmentation
        logger.debug(f">>> AVRCP response PDU: {response}")
        pdu = (
            struct.pack(">BBH", response.pdu_id, 0, len(response.parameter))
            + response.parameter
        )
        response_frame = avc.VendorDependentResponseFrame(
            response_code,
            avc.Frame.SubunitType.PANEL,
            0,
            AVRCP_BLUETOOTH_SIG_COMPANY_ID,
            pdu,
        )
        self.send_response(self.receive_command_state.transaction_label, response_frame)

    def send_not_implemented_response(
        self, transaction_label: int, command: avc.CommandFrame
    ) -> None:
        response = avc.ResponseFrame(
            avc.ResponseFrame.ResponseCode.NOT_IMPLEMENTED,
            command.subunit_type,
            command.subunit_id,
            command.opcode,
            command.operands,
        )
        self.send_response(transaction_label, response)

    def send_rejected_response_pdu(
        self, pdu_id: Protocol.PduId, status_code: StatusCode
    ) -> None:
        self.send_response_pdu(
            avc.ResponseFrame.ResponseCode.REJECTED,
            RejectedResponse(pdu_id, status_code),
        )

    def on_get_capabilities_command(self, command: GetCapabilitiesCommand) -> None:
        logger.debug(f"<<< AVRCP command PDU: {command}")

        if (
            command.capability_id
            == GetCapabilitiesCommand.CapabilityId.EVENTS_SUPPORTED
        ):
            # TEST: hardcoded values for testing only
            supported_events = [EventId.VOLUME_CHANGED, EventId.PLAYBACK_STATUS_CHANGED]
            self.send_response_pdu(
                avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE,
                GetCapabilitiesResponse(command.capability_id, supported_events),
            )
            return

        self.send_rejected_response_pdu(
            self.PduId.GET_CAPABILITIES, self.StatusCode.INVALID_PARAMETER
        )

    def on_set_absolute_volume_command(self, command: SetAbsoluteVolumeCommand) -> None:
        logger.debug(f"<<< AVRCP command PDU: {command}")

        # TODO implement a delegate
        self.send_response_pdu(
            avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE,
            SetAbsoluteVolumeResponse(command.volume),
        )

    def on_register_notification_command(
        self, command: RegisterNotificationCommand
    ) -> None:
        logger.debug(f"<<< AVRCP command PDU: {command}")

        if command.event_id == EventId.VOLUME_CHANGED:
            response = RegisterNotificationResponse(
                command.event_id, bytes([10])
            )  # TODO: testing only
            self.send_response_pdu(avc.ResponseFrame.ResponseCode.INTERIM, response)
            return

        self.send_rejected_response_pdu(
            self.PduId.REGISTER_NOTIFICATION, self.StatusCode.INVALID_PARAMETER
        )
