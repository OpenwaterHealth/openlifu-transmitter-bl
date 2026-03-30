import argparse
import hashlib
import hmac
import os
import struct
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, Prehashed
except ImportError:
    serialization = None
    ec = None
    decode_dss_signature = None
    Prehashed = None


APP_ADDRESS_DEFAULT = 0x08010000
META_ADDRESS_DEFAULT = 0x0800F800
APPLICATION_MAX_SIZE_DEFAULT = 190 * 1024

META_MAGIC = 0x314D4657  # 'WFM1'
META_VERSION = 3
META_FLAGS_SIGNATURE_REQUIRED = 1
TRUST_TAG_SIZE_BYTES = 32
META_STRUCT_WITHOUT_CRC = "<IHHIIII64s32s"

SIGNED_PKG_MAGIC = 0x314B4750  # 'PGK1'
SIGNED_PKG_VERSION = 1
SIGNED_PKG_HEADER_NOCRC = "<IHHIIIII"


def stm32_crc32(data: bytes, init: int = 0xFFFFFFFF) -> int:
    poly = 0x04C11DB7
    crc = init & 0xFFFFFFFF
    for b in data:
        crc ^= (b & 0xFF) << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ poly) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc


def _require_cryptography() -> None:
    if serialization is None or ec is None or decode_dss_signature is None or Prehashed is None:
        raise RuntimeError("Missing dependency 'cryptography'. Install with: python -m pip install cryptography")


def _load_private_key(key_bytes: bytes):
    _require_cryptography()

    if b"-----BEGIN" in key_bytes:
        return serialization.load_pem_private_key(key_bytes, password=None)

    if len(key_bytes) == 32:
        d = int.from_bytes(key_bytes, "big")
        if d <= 0:
            raise ValueError("Invalid raw private key scalar (must be non-zero)")
        return ec.derive_private_key(d, ec.SECP256R1())

    raise ValueError("Unsupported private key format: expected PEM private key or raw 32-byte scalar")


def _ecdsa_p256_sign_raw(private_key_bytes: bytes, digest32: bytes) -> bytes:
    if len(digest32) != 32:
        raise ValueError("digest must be 32 bytes")

    priv = _load_private_key(private_key_bytes)
    der_sig = priv.sign(digest32, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _load_trust_key(key_bytes: bytes) -> bytes:
    # First, handle raw binary keys without modifying the bytes.
    if len(key_bytes) == 32:
        return key_bytes

    # For hex-encoded keys, allow surrounding whitespace and decode from ASCII hex.
    raw = key_bytes.strip()
    if len(raw) == 64:
        try:
            decoded = bytes.fromhex(raw.decode("ascii"))
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass

    raise ValueError("Unsupported trust key format: expected 32-byte raw key or 64-char hex")


def _is_sp_sane(sp: int) -> bool:
    return (sp & 0x2FFE0000) == 0x20000000


def _is_rv_sane(rv: int, app_address: int, app_max_size: int) -> bool:
    rv_addr = rv & ~1
    return (rv & 1) == 1 and app_address <= rv_addr < (app_address + app_max_size)


def validate_vector_table(fw: bytes, app_address: int, app_max_size: int) -> tuple[int, int]:
    if len(fw) < 8:
        raise ValueError("Firmware image too small: must contain at least vector SP + reset vector")

    sp = struct.unpack_from("<I", fw, 0)[0]
    rv = struct.unpack_from("<I", fw, 4)[0]

    if not _is_sp_sane(sp):
        raise ValueError(f"Vector SP is not sane: 0x{sp:08X}")
    if not _is_rv_sane(rv, app_address, app_max_size):
        raise ValueError(
            f"Reset vector out of expected app range or not Thumb: rv=0x{rv:08X}, "
            f"expected in [0x{app_address:08X}, 0x{app_address + app_max_size:08X})"
        )

    return sp, rv


def build_metadata_blob(
    fw_bytes: bytes,
    signing_key_bytes: bytes,
    fw_address: int,
    key_id: int,
    trust_key_bytes: bytes | None,
) -> bytes:
    fw_len = len(fw_bytes)
    fw_crc = stm32_crc32(fw_bytes)
    digest = hashlib.sha256(fw_bytes).digest()
    signature = _ecdsa_p256_sign_raw(signing_key_bytes, digest)

    if trust_key_bytes:
        trust_tag = hmac.new(trust_key_bytes, digestmod=hashlib.sha256)
        trust_tag.update(
            struct.pack(
                "<IHHIIII64s",
                META_MAGIC,
                META_VERSION,
                META_FLAGS_SIGNATURE_REQUIRED,
                fw_address,
                fw_len,
                fw_crc,
                key_id,
                signature,
            )
        )
        trust_tag_bytes = trust_tag.digest()
    else:
        trust_tag_bytes = bytes(TRUST_TAG_SIZE_BYTES)

    meta_wo_crc = struct.pack(
        META_STRUCT_WITHOUT_CRC,
        META_MAGIC,
        META_VERSION,
        META_FLAGS_SIGNATURE_REQUIRED,
        fw_address,
        fw_len,
        fw_crc,
        key_id,
        signature,
        trust_tag_bytes,
    )
    meta_crc = stm32_crc32(meta_wo_crc)
    return meta_wo_crc + struct.pack("<I", meta_crc)


def build_signed_package(fw: bytes, meta: bytes, fw_address: int, meta_address: int) -> bytes:
    header_size = struct.calcsize("<IHHIIIIII")
    payload = fw + meta
    payload_crc = stm32_crc32(payload)

    header_wo_crc = struct.pack(
        SIGNED_PKG_HEADER_NOCRC,
        SIGNED_PKG_MAGIC,
        SIGNED_PKG_VERSION,
        header_size,
        fw_address,
        len(fw),
        meta_address,
        len(meta),
        payload_crc,
    )
    header_crc = stm32_crc32(header_wo_crc)
    header = header_wo_crc + struct.pack("<I", header_crc)
    return header + payload


def _parse_int(value: str) -> int:
    return int(value, 0)


def main() -> None:
    p = argparse.ArgumentParser(
        description="Create a signed firmware package (no relocation) for bootloader DFU program-package"
    )
    p.add_argument("infile", help="Input application firmware binary")
    p.add_argument("keyfile", help="Signing key file (PEM private key or raw 32-byte scalar)")
    p.add_argument("--outfile", default=None, help="Output signed package path (default: <infile>.signed.bin)")
    p.add_argument("--meta-out", default=None, help="Optional metadata output path")
    p.add_argument("--address", type=_parse_int, default=APP_ADDRESS_DEFAULT)
    p.add_argument("--meta-address", type=_parse_int, default=META_ADDRESS_DEFAULT)
    p.add_argument("--key-id", type=_parse_int, default=1)
    p.add_argument("--trust-keyfile", default=None, help="Optional trust HMAC key file")
    p.add_argument("--max-app-size", type=_parse_int, default=APPLICATION_MAX_SIZE_DEFAULT)
    p.add_argument(
        "--skip-vector-check",
        action="store_true",
        help="Skip SP/reset-vector sanity checks (not recommended)",
    )

    args = p.parse_args()

    fw_path = Path(args.infile)
    with fw_path.open("rb") as f:
        fw = f.read()

    if len(fw) == 0:
        raise SystemExit("Firmware image is empty")
    if len(fw) > args.max_app_size:
        raise SystemExit(f"Firmware image too large: {len(fw)} > max {args.max_app_size}")

    if not args.skip_vector_check:
        sp, rv = validate_vector_table(fw, args.address, args.max_app_size)
        print(f"Vector table check OK: SP=0x{sp:08X}, Reset=0x{rv:08X}")

    with open(args.keyfile, "rb") as f:
        key = f.read()

    trust_key = None
    if args.trust_keyfile:
        with open(args.trust_keyfile, "rb") as f:
            trust_key = _load_trust_key(f.read())

    meta = build_metadata_blob(fw, key, args.address, args.key_id, trust_key)
    pkg = build_signed_package(fw, meta, args.address, args.meta_address)

    if args.outfile is None:
        outfile = fw_path.with_suffix(fw_path.suffix + ".signed.bin")
    else:
        outfile = Path(args.outfile)

    with outfile.open("wb") as f:
        f.write(pkg)

    if args.meta_out:
        with open(args.meta_out, "wb") as f:
            f.write(meta)

    print(f"Signed package written: {outfile}")
    print(f"  firmware bytes: {len(fw)} at 0x{args.address:08X}")
    print(f"  metadata bytes: {len(meta)} at 0x{args.meta_address:08X}")
    if trust_key is None:
        print("  trust_tag: unsealed (all zeros)")
    else:
        print("  trust_tag: sealed")

    rel_out = os.path.relpath(str(outfile), str(Path.cwd()))
    flash_script = Path("test") / "dfu-test.py"
    print("\nFlash with:")
    print(f"python {flash_script.as_posix()} program-package {rel_out} --manifest")


if __name__ == "__main__":
    main()
