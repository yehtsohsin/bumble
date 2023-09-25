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
import asyncio
import sys
import os
import logging

from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.core import BT_BR_EDR_TRANSPORT
from bumble import avc
from bumble import avctp
from bumble import avrcp
from bumble import avdtp
from bumble import a2dp
from bumble import l2cap

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
def sdp_records():
    a2dp_sink_service_record_handle = 0x00010001
    avrcp_controller_service_record_handle = 0x00010002
    avrcp_target_service_record_handle = 0x00010003
    # pylint: disable=line-too-long
    return {
        a2dp_sink_service_record_handle: a2dp.make_audio_sink_service_sdp_records(
            a2dp_sink_service_record_handle
        ),
        avrcp_controller_service_record_handle: avrcp.make_controller_service_sdp_records(
            avrcp_controller_service_record_handle
        ),
        avrcp_target_service_record_handle: avrcp.make_target_service_sdp_records(
            avrcp_controller_service_record_handle
        ),
    }


# -----------------------------------------------------------------------------
def codec_capabilities():
    return avdtp.MediaCodecCapabilities(
        media_type=avdtp.AVDTP_AUDIO_MEDIA_TYPE,
        media_codec_type=a2dp.A2DP_SBC_CODEC_TYPE,
        media_codec_information=a2dp.SbcMediaCodecInformation.from_lists(
            sampling_frequencies=[48000, 44100, 32000, 16000],
            channel_modes=[
                a2dp.SBC_MONO_CHANNEL_MODE,
                a2dp.SBC_DUAL_CHANNEL_MODE,
                a2dp.SBC_STEREO_CHANNEL_MODE,
                a2dp.SBC_JOINT_STEREO_CHANNEL_MODE,
            ],
            block_lengths=[4, 8, 12, 16],
            subbands=[4, 8],
            allocation_methods=[
                a2dp.SBC_LOUDNESS_ALLOCATION_METHOD,
                a2dp.SBC_SNR_ALLOCATION_METHOD,
            ],
            minimum_bitpool_value=2,
            maximum_bitpool_value=53,
        ),
    )


# -----------------------------------------------------------------------------
def on_avdtp_connection(server):
    # Add a sink endpoint to the server
    sink = server.add_sink(codec_capabilities())
    sink.on('rtp_packet', on_rtp_packet)


# -----------------------------------------------------------------------------
def on_rtp_packet(packet):
    print(f'RTP: {packet}')


# -----------------------------------------------------------------------------
def on_avctp_connection(l2cap_channel: l2cap.Channel) -> None:
    logger.debug(f'+++ new L2CAP connection: {l2cap_channel}')
    _ = avrcp.Protocol(l2cap_channel)
    #l2cap_channel.on('open', lambda: on_avctp_channel_open(l2cap_channel))


# def on_avctp_channel_open(l2cap_channel: l2cap.Channel) -> None:
#     logger.debug(f'$$$ AVCTP channel open: {l2cap_channel}')

#     l2cap_channel.on('close', on_avctp_channel_close)
#     avctp_protocol = avctp.Protocol(l2cap_channel)
#     avctp_protocol.register_command_handler(avrcp.AVRCP_PID, on_avctp_command)
#     avctp_protocol.register_response_handler(avrcp.AVRCP_PID, on_avctp_response)

#     play_pressed = avc.PassThroughCommandFrame(
#         avc.CommandFrame.CommandType.CONTROL,
#         avc.CommandFrame.SubunitType.PANEL,
#         0,
#         avc.PassThroughCommandFrame.StateFlag.PRESSED,
#         avc.PassThroughCommandFrame.OperationId.PLAY,
#         b'',
#     )
#     avctp_protocol.send_command(1, avrcp.AVRCP_PID, bytes(play_pressed))

#     play_released = avc.PassThroughCommandFrame(
#         avc.CommandFrame.CommandType.CONTROL,
#         avc.CommandFrame.SubunitType.PANEL,
#         0,
#         avc.PassThroughCommandFrame.StateFlag.RELEASED,
#         avc.PassThroughCommandFrame.OperationId.PLAY,
#         b'',
#     )
#     avctp_protocol.send_command(2, avrcp.AVRCP_PID, bytes(play_released))


def on_avctp_channel_close():
    logger.debug('&&& AVCTP channel close')


def on_avctp_pdu(pdu):
    logger.debug(f'AVCTP PDU: {pdu.hex()}')


def on_avctp_command(transaction_label, command):
    print(f">>> AVCTP Command, transaction_label={transaction_label}: {command.hex()}")
    frame = avc.Frame.from_bytes(command)
    print(frame)


def on_avctp_response(transaction_label, response):
    print(
        f">>> AVCTP Response, transaction_label={transaction_label}: {response.hex()}"
    )
    frame = avc.Frame.from_bytes(response)
    print(frame)


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 3:
        print(
            'Usage: run_avrcp_controller.py <device-config> <transport-spec> '
            '<sbc-file> [<bt-addr>]'
        )
        print('example: run_avrcp_controller.py classic1.json usb:0')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
        device.classic_enabled = True

        # Setup the SDP to expose the sink service
        device.sdp_service_records = sdp_records()

        # Start the controller
        await device.power_on()

        # Create a listener to wait for AVDTP connections
        listener = avdtp.Listener(avdtp.Listener.create_registrar(device))
        listener.on('connection', on_avdtp_connection)

        device.register_l2cap_server(avctp.AVCTP_PSM, on_avctp_connection)

        if len(sys.argv) >= 5:
            # Connect to the source
            target_address = sys.argv[4]
            print(f'=== Connecting to {target_address}...')
            connection = await device.connect(
                target_address, transport=BT_BR_EDR_TRANSPORT
            )
            print(f'=== Connected to {connection.peer_address}!')

            # Request authentication
            print('*** Authenticating...')
            await connection.authenticate()
            print('*** Authenticated')

            # Enable encryption
            print('*** Enabling encryption...')
            await connection.encrypt()
            print('*** Encryption on')

            server = await avdtp.Protocol.connect(connection)
            listener.set_server(connection, server)
            sink = server.add_sink(codec_capabilities())
            sink.on('rtp_packet', on_rtp_packet)
        else:
            # Start being discoverable and connectable
            await device.set_discoverable(True)
            await device.set_connectable(True)

        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
