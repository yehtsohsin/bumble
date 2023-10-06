# Copyright 2021-2022 Google LLC
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

from bumble.colors import color
from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.core import BT_BR_EDR_TRANSPORT
from bumble.avdtp import (
    find_avdtp_service_with_connection,
    AVDTP_AUDIO_MEDIA_TYPE,
    MediaCodecCapabilities,
    MediaPacketPump,
    Protocol,
    Listener,
)
from bumble import avc
from bumble import avctp
from bumble import avrcp
from bumble.a2dp import (
    SBC_JOINT_STEREO_CHANNEL_MODE,
    SBC_LOUDNESS_ALLOCATION_METHOD,
    make_audio_source_service_sdp_records,
    A2DP_SBC_CODEC_TYPE,
    SbcMediaCodecInformation,
    SbcPacketSource,
)
from bumble import l2cap


logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
def sdp_records():
    service_record_handle = 0x00010001
    return {
        service_record_handle: make_audio_source_service_sdp_records(
            service_record_handle
        )
    }


# -----------------------------------------------------------------------------
def codec_capabilities():
    # NOTE: this shouldn't be hardcoded, but should be inferred from the input file
    # instead
    return MediaCodecCapabilities(
        media_type=AVDTP_AUDIO_MEDIA_TYPE,
        media_codec_type=A2DP_SBC_CODEC_TYPE,
        media_codec_information=SbcMediaCodecInformation.from_discrete_values(
            sampling_frequency=44100,
            channel_mode=SBC_JOINT_STEREO_CHANNEL_MODE,
            block_length=16,
            subbands=8,
            allocation_method=SBC_LOUDNESS_ALLOCATION_METHOD,
            minimum_bitpool_value=2,
            maximum_bitpool_value=53,
        ),
    )


# -----------------------------------------------------------------------------
def on_avdtp_connection():
    logger.debug("$$$ AVDTP Connection")


# -----------------------------------------------------------------------------
async def stream_packets(read_function, protocol):
    # Discover all endpoints on the remote device
    endpoints = await protocol.discover_remote_endpoints()
    for endpoint in endpoints:
        print('@@@', endpoint)

    # Select a sink
    sink = protocol.find_remote_sink_by_codec(
        AVDTP_AUDIO_MEDIA_TYPE, A2DP_SBC_CODEC_TYPE
    )
    if sink is None:
        print(color('!!! no SBC sink found', 'red'))
        return
    print(f'### Selected sink: {sink.seid}')

    # Stream the packets
    packet_source = SbcPacketSource(
        read_function, protocol.l2cap_channel.mtu, codec_capabilities()
    )
    packet_pump = MediaPacketPump(packet_source.packets)
    source = protocol.add_source(packet_source.codec_capabilities, packet_pump)
    stream = await protocol.create_stream(source, sink)
    await stream.start()
    await asyncio.sleep(5)
    await stream.stop()
    await asyncio.sleep(5)
    await stream.start()
    await asyncio.sleep(5)
    await stream.stop()
    await stream.close()


# -----------------------------------------------------------------------------
def on_avctp_connection(l2cap_channel: l2cap.Channel) -> None:
    logger.debug(f'+++ new L2CAP connection: {l2cap_channel}')
    l2cap_channel.on('open', lambda: on_avctp_l2cap_channel_open(l2cap_channel))


def on_avctp_l2cap_channel_open(l2cap_channel: l2cap.Channel) -> None:
    logger.debug(f'$$$ L2CAP channel open: {l2cap_channel}')
    l2cap_channel.sink = on_avctp_pdu


def on_avctp_pdu(pdu):
    logger.debug(f'AVCTP PDU: {pdu.hex()}')


def on_avctp_channel_open():
    logger.debug('### AVCTP channel open')


def on_avctp_channel_close():
    logger.debug('&&& AVCTP channel close')


def on_avctp_command(transaction_label, command):
    print(f"<<< AVCTP Command, transaction_label={transaction_label}: {command.hex()}")
    frame = avc.Frame.from_bytes(command)
    print(frame)


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 3:
        print(
            'Usage: run_avrcp_target.py <device-config> <transport-spec>'
            '[<bluetooth-address>]'
        )
        print('example: run_avrcp_target.py classic1.json usb:0 E1:CA:72:48:C4:E8')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
        device.classic_enabled = True

        # Setup the SDP to expose the SRC service
        device.sdp_service_records = sdp_records()

        # Start
        await device.power_on()

        device.register_l2cap_server(avctp.AVCTP_PSM, on_avctp_connection)

        if len(sys.argv) > 3:
            # Connect to a peer
            target_address = sys.argv[3]
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

            # Create a client to interact with the remote device
            await Protocol.connect(connection, (1, 2))

            print("------------------ connecting to AVCTP -----------")
            connector = connection.create_l2cap_connector(avctp.AVCTP_PSM)
            avctp_channel = await connector()
            print("++++++ connected")
            avctp_channel.sink = on_avctp_pdu
            avctp_channel.on('open', on_avctp_channel_open)
            avctp_channel.on('close', on_avctp_channel_close)

            avrcp_protocol = avrcp.Protocol()
            avctp_protocol = avctp.Protocol(avctp_channel)
            avctp_protocol.register_command_handler(avrcp.AVRCP_PID, on_avctp_command)
        else:
            # Create a listener to wait for AVDTP connections
            listener = Listener(Listener.create_registrar(device), version=(1, 2))
            listener.on('connection', lambda protocol: on_avdtp_connection())

            # Become connectable and wait for a connection
            await device.set_discoverable(True)
            await device.set_connectable(True)

        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
