# Copyright (c) 2026 The ElectrumX authors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import struct

import pytest

from electrumx.lib.coins import Verge
from electrumx.lib.hash import double_sha256
from electrumx.lib.tx import DeserializerVerge


POS_VERSION = Verge.POS_VERSION_BIT | 2
POS_TX_VERSION = DeserializerVerge.POS_REPLAY_PROTECTED_VERSION
POS_REPLAY_MARKER = DeserializerVerge.POS_REPLAY_MARKER


def make_pos_header():
    return b''.join((
        struct.pack('<I', POS_VERSION),
        bytes.fromhex('11' * 32),
        bytes.fromhex('22' * 32),
        struct.pack('<III', 1_800_000_000, 0x1D00FFFF, 0),
        bytes.fromhex('33' * 32),
    ))


def make_pos_transaction(marker=POS_REPLAY_MARKER):
    return b''.join((
        struct.pack('<II', POS_TX_VERSION, 1_800_000_000),
        struct.pack('<I', marker),
        b'\x01',
        bytes(32),
        struct.pack('<I', 0xFFFFFFFF),
        b'\x00',
        struct.pack('<I', 0xFFFFFFFF),
        b'\x01',
        struct.pack('<q', 1_000_000),
        b'\x01\x51',
        struct.pack('<I', 0),
    ))


def test_pos_header_and_transaction_are_parsed():
    header = make_pos_header()
    raw_tx = make_pos_transaction()
    block = Verge.block(header + b'\x01' + raw_tx, 1)

    assert len(block.header) == Verge.POS_HEADER_SIZE
    assert Verge.header_hash_rev(block.header) == double_sha256(header)
    assert len(block.transactions) == 1
    assert block.transactions[0].version == POS_TX_VERSION
    assert block.transactions[0].time == 1_800_000_000
    assert block.transactions[0].txid_rev == double_sha256(raw_tx)


def test_pow_header_remains_80_bytes():
    header = struct.pack('<I', 4) + bytes(76)
    assert Verge.block_header(header + b'\x00', 1) == header


def test_invalid_pos_replay_marker_is_rejected():
    with pytest.raises(ValueError, match='replay marker'):
        DeserializerVerge(make_pos_transaction(marker=0)).read_tx()
