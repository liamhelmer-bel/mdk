"""Test-only actual Product producer/Git bytes; synthetic HTTPS/rendering, no consent."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--product', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--group-hex', required=True)
parser.add_argument('--pad-original', action='store_true')
args = parser.parse_args()
if not 16 <= len(bytes.fromhex(args.group_hex)) <= 64:
    raise ValueError("Product group must be16–64bytes, independently of Nostr routing")
sys.path[:0] = [str(args.product / 'src'), str(args.product / 'tests')]
import msgspec
import pytest
import test_deployment_outage as outage
import test_deployment_publication as publication
import test_deployment_producer_process as process
from heterodyne.actions import deployment_authority as authority
from heterodyne.actions.codec import encode_record
from heterodyne.actions.deployment import digest
from heterodyne.actions.deployment_outage import decode_packet

now = time.time_ns()
p = outage.packet()
r = msgspec.structs.replace(p.release, not_before_ns=now - 1_000_000_000,
    deadline_ns=now + 1_800_000_000_000,
    recovery=msgspec.structs.replace(p.release.recovery, deadline_ns=now + 3_600_000_000_000))
p = msgspec.structs.replace(p, release=r, outage=msgspec.structs.replace(p.outage,
    release_sha256=digest(r), not_before_ns=now,
    deadline_ns=now + 1_200_000_000_000, recovery_deadline_ns=r.recovery.deadline_ns))
assert decode_packet(encode_record(p), (process.TARGET,)) == p
with tempfile.TemporaryDirectory(prefix='whole-packet-') as directory, pytest.MonkeyPatch.context() as patch:
    patch.setattr(publication, 'packet', lambda: p)
    patch.setattr(authority, '_rendering', lambda: ((), 2000))
    patch.setattr(process, 'H', args.group_hex)
    pub = publication.published.__wrapped__(Path(directory), patch)
    values = next(pub)
    inp = process.inputs.__wrapped__(values, Path(directory))
    inputs = next(inp)
    if args.pad_original:
        original = inputs[0]
        if len(original) > 32768:
            raise ValueError("fixture already exceeds original packet bound")
        original += b' ' * (32768 - len(original))
        assert decode_packet(original, (process.TARGET,)) == p
        profile = msgspec.structs.replace(inputs[2],
            operation_original_sha256=hashlib.sha256(original).hexdigest())
        inputs[6].chmod(0o600)
        inputs[6].write_bytes(encode_record(profile))
        inputs[6].chmod(0o400)
        inputs = (original, inputs[1], profile, *inputs[3:])
    try:
        result = process.child(inputs)
        if result.returncode != 0:
            raise RuntimeError((result.returncode, result.stderr.decode(errors='replace')))
        output = process.producer._check_output(result.stdout, inputs[0], inputs[2])
        payload = {'schema':'heterodyne-owned-card-process-fixture.v1',
            'qualification':'TEST ONLY: actual isolated Product child and Git proof; synthetic HTTPS/rendering; finite current times. Not enrolled custody, human consent or deployment authority.',
            'generated_at_unix_ns':now,'expires_at_unix_ns':p.outage.deadline_ns,
            'product_head':process.subprocess.check_output(['git','-C',str(args.product),'rev-parse','HEAD'],text=True).strip(),
            'output_original_base64':base64.b64encode(result.stdout).decode('ascii'),
            'output':json.loads(result.stdout)}
        args.output.write_text(json.dumps(payload, indent=2)+'\n')
        args.output.chmod(0o600)
        if args.pad_original:
            args.output.with_suffix('.producer.json').write_bytes(encode_record(inputs[2]))
            args.output.with_suffix('.packet.json').write_bytes(inputs[0])
        print(json.dumps({'output':str(args.output),'sha256':hashlib.sha256(args.output.read_bytes()).hexdigest(),
            'original_sha256':hashlib.sha256(output.operation_original).hexdigest(),
            'packet_sha256':output.packet_sha256,'expires_at_unix_ns':p.outage.deadline_ns}))
    finally:
        inp.close()
        pub.close()
