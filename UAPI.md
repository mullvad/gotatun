In addition to the standard UAPI [configuration protocol], GotaTun includes some non-standard
extensions when some features are enabled.

[configuration protocol]: https://www.wireguard.com/xplatform/#configuration-protocol

# DAITA - Defence Against AI-Guided Traffic Analysis

If GotaTun is built with `--features daita-uapi`, the following keys are available when adding or
modifying a peer:

* `daita_enable`: Set to `1` to enable or replace existing settings, or `0` to disable DAITA.
* `daita_machine`: A base64-encoded [Maybenot] machine.
* `daita_max_delayed_packets`: Maximum number of packets that may be delayed at any time.
* `daita_min_delay_capacity`: Minimum number of free slots in the delay queue to continue
  delaying packets.
* `daita_max_padding_frac`: Maximum fraction of padding packets in `[0, 1]`.
* `daita_max_delay_frac`: Maximum fraction of delayed packets in `[0, 1]`.

In addition to the keys above, the following ones are available when retrieving a peer (`get=1`):

* `daita_rx_padding_bytes`: Extra bytes added due to constant-size padding of data packets for the
  previously added peer entry.
* `daita_tx_padding_bytes`: Bytes of standalone padding packets transmitted for the previously added
  peer entry.
* `daita_rx_padding_packet_bytes`: Total extra bytes removed due to constant-size padding of data
  packets for the previously added peer entry.
* `daita_tx_padding_packet_bytes`: Bytes of standalone padding packets received for the previously
  added peer entry.

[Maybenot]: https://docs.rs/maybenot/latest/maybenot/struct.Machine.html
