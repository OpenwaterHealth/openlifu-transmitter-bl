import argparse
import hmac
import hashlib
import sys
import struct
import time

import usb.core
import usb.util
import usb.backend.libusb1

try:
	from cryptography.hazmat.primitives import hashes, serialization
	from cryptography.hazmat.primitives.asymmetric import ec
	from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature, Prehashed
except ImportError:
	serialization = None
	ec = None
	decode_dss_signature = None
	encode_dss_signature = None
	Prehashed = None

try:
	import libusb_package
except ImportError:
	libusb_package = None


APP_ADDRESS_DEFAULT = 0x08010000
META_ADDRESS_DEFAULT = 0x0800F800
META_MAGIC = 0x314D4657  # 'WFM1'
META_VERSION = 3
META_FLAGS_SIGNATURE_REQUIRED = 1
SIGNATURE_SIZE_BYTES = 64
TRUST_TAG_SIZE_BYTES = 32

# Virtual read address used by the bootloader's MEM_If_Read_FS to return the
# version string via a standard DFU UPLOAD.  Must match DFU_VERSION_VIRT_ADDR
# in usbd_dfu_if.c.
DFU_VERSION_VIRT_ADDR = 0xFFFFFF00
DFU_VERSION_READ_LEN  = 64

# Virtual write address used by the bootloader's MEM_If_Write_FS to trigger a
# system reset via NVIC_SystemReset().  Must match DFU_RESET_VIRT_ADDR in
# usbd_dfu_if.c.
DFU_RESET_VIRT_ADDR = 0xFFFFFF08
META_STRUCT_WITHOUT_CRC = "<IHHIIII64s32s"
META_STRUCT_FULL = "<IHHIIII64s32sI"
DEFAULT_RELOCATE_WINDOW = 190 * 1024

SIGNED_PKG_MAGIC = 0x314B4750  # 'PGK1'
SIGNED_PKG_VERSION = 1
SIGNED_PKG_HEADER_NOCRC = "<IHHIIIII"
SIGNED_PKG_HEADER_FULL = "<IHHIIIIII"


def stm32_crc32(data: bytes, init: int = 0xFFFFFFFF) -> int:
	"""CRC compatible with STM32 CRC peripheral default settings (poly 0x04C11DB7)."""
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
		raise RuntimeError(
			"Missing dependency 'cryptography'. Install with: python -m pip install cryptography"
		)


def _load_private_key(key_bytes: bytes):
	_require_cryptography()

	# PEM private key
	if b"-----BEGIN" in key_bytes:
		return serialization.load_pem_private_key(key_bytes, password=None)

	# Raw 32-byte private scalar (big-endian)
	if len(key_bytes) == 32:
		d = int.from_bytes(key_bytes, "big")
		if d <= 0:
			raise ValueError("Invalid raw private key scalar (must be non-zero)")
		return ec.derive_private_key(d, ec.SECP256R1())

	raise ValueError("Unsupported private key format: expected PEM private key or raw 32-byte scalar")


def _load_public_key(key_bytes: bytes):
	_require_cryptography()

	if b"-----BEGIN" in key_bytes:
		try:
			key = serialization.load_pem_public_key(key_bytes)
		except ValueError:
			key = serialization.load_pem_private_key(key_bytes, password=None).public_key()

		if not isinstance(key, ec.EllipticCurvePublicKey):
			raise ValueError("Provided PEM key is not an EC key")
		return key

	# Raw uncompressed point without 0x04 prefix (x||y)
	if len(key_bytes) == 64:
		x = int.from_bytes(key_bytes[:32], "big")
		y = int.from_bytes(key_bytes[32:], "big")
		pub_nums = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
		return pub_nums.public_key()

	# Raw private scalar can also be used for verify by deriving pub
	if len(key_bytes) == 32:
		return _load_private_key(key_bytes).public_key()

	raise ValueError("Unsupported verification key format: expected PEM public/private key, raw 64-byte x||y public key, or raw 32-byte private scalar")


def _ecdsa_p256_sign_raw(private_key_bytes: bytes, digest32: bytes) -> bytes:
	if len(digest32) != 32:
		raise ValueError("digest must be 32 bytes")

	priv = _load_private_key(private_key_bytes)
	der_sig = priv.sign(digest32, ec.ECDSA(Prehashed(hashes.SHA256())))
	r, s = decode_dss_signature(der_sig)
	return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _ecdsa_p256_verify_raw(public_or_private_key_bytes: bytes, digest32: bytes, sig64: bytes) -> bool:
	if len(digest32) != 32:
		raise ValueError("digest must be 32 bytes")
	if len(sig64) != 64:
		raise ValueError("signature must be 64 bytes")

	pub = _load_public_key(public_or_private_key_bytes)
	r = int.from_bytes(sig64[:32], "big")
	s = int.from_bytes(sig64[32:], "big")
	der_sig = encode_dss_signature(r, s)

	try:
		pub.verify(der_sig, digest32, ec.ECDSA(Prehashed(hashes.SHA256())))
		return True
	except Exception:
		return False


def _load_trust_key(key_bytes: bytes) -> bytes:
	"""Load trust HMAC key from raw bytes or ASCII hex string."""
	raw = key_bytes.strip()
	if len(raw) == 32:
		return raw

	if len(raw) == 64:
		try:
			decoded = bytes.fromhex(raw.decode("ascii"))
			if len(decoded) == 32:
				return decoded
		except Exception:
			pass

	raise ValueError("Unsupported trust key format: expected 32-byte raw key or 64-char hex")


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


def parse_metadata_blob(meta: bytes):
	if len(meta) < struct.calcsize(META_STRUCT_FULL):
		raise ValueError("metadata blob too small")
	return struct.unpack(META_STRUCT_FULL, meta[: struct.calcsize(META_STRUCT_FULL)])


def build_signed_package(fw: bytes, meta: bytes, fw_address: int, meta_address: int) -> bytes:
	header_size = struct.calcsize(SIGNED_PKG_HEADER_FULL)
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


def parse_signed_package(pkg: bytes):
	header_size = struct.calcsize(SIGNED_PKG_HEADER_FULL)
	if len(pkg) < header_size:
		raise ValueError("signed package too small")

	(
		magic,
		version,
		declared_header_size,
		fw_address,
		fw_len,
		meta_address,
		meta_len,
		payload_crc,
		header_crc,
	) = struct.unpack(SIGNED_PKG_HEADER_FULL, pkg[:header_size])

	if magic != SIGNED_PKG_MAGIC:
		raise ValueError("signed package magic mismatch")
	if version != SIGNED_PKG_VERSION:
		raise ValueError(f"signed package version mismatch: {version}")
	if declared_header_size != header_size:
		raise ValueError("signed package header size mismatch")

	calc_header_crc = stm32_crc32(pkg[: header_size - 4])
	if header_crc != calc_header_crc:
		raise ValueError(
			f"signed package header CRC mismatch: pkg=0x{header_crc:08X}, calc=0x{calc_header_crc:08X}"
		)

	payload_len = fw_len + meta_len
	payload = pkg[header_size:]
	if len(payload) != payload_len:
		raise ValueError(
			f"signed package payload size mismatch: expected={payload_len}, file={len(payload)}"
		)

	calc_payload_crc = stm32_crc32(payload)
	if payload_crc != calc_payload_crc:
		raise ValueError(
			f"signed package payload CRC mismatch: pkg=0x{payload_crc:08X}, calc=0x{calc_payload_crc:08X}"
		)

	fw = payload[:fw_len]
	meta = payload[fw_len:]

	return {
		"fw_address": fw_address,
		"meta_address": meta_address,
		"fw": fw,
		"meta": meta,
	}


def verify_metadata_against_firmware(
	fw: bytes,
	key: bytes,
	meta_blob: bytes,
	trust_key: bytes | None,
) -> tuple[bool, list[str], int, int, int]:
	(magic, version, flags, fw_addr, fw_len, fw_crc, key_id, signature, trust_tag, meta_crc) = parse_metadata_blob(meta_blob)
	calc_meta_crc = stm32_crc32(meta_blob[: struct.calcsize(META_STRUCT_WITHOUT_CRC)])
	calc_fw_crc = stm32_crc32(fw)
	calc_fw_digest = hashlib.sha256(fw).digest()
	signature_ok = _ecdsa_p256_verify_raw(key, calc_fw_digest, signature)

	trust_ok = None
	if trust_key is not None:
		msg = struct.pack(
			"<IHHIIII64s",
			magic,
			version,
			flags,
			fw_addr,
			fw_len,
			fw_crc,
			key_id,
			signature,
		)
		trust_ok = hmac.compare_digest(hmac.new(trust_key, msg, hashlib.sha256).digest(), trust_tag)

	messages: list[str] = []
	ok = True
	if magic != META_MAGIC or version != META_VERSION:
		messages.append("Metadata magic/version mismatch")
		ok = False
	if flags != META_FLAGS_SIGNATURE_REQUIRED:
		messages.append(f"Metadata flags mismatch: meta=0x{flags:04X}, expected=0x{META_FLAGS_SIGNATURE_REQUIRED:04X}")
		ok = False
	if fw_len != len(fw):
		messages.append(f"Firmware length mismatch: meta={fw_len}, file={len(fw)}")
		ok = False
	if fw_crc != calc_fw_crc:
		messages.append(f"Firmware CRC mismatch: meta=0x{fw_crc:08X}, calc=0x{calc_fw_crc:08X}")
		ok = False
	if meta_crc != calc_meta_crc:
		messages.append(f"Metadata CRC mismatch: meta=0x{meta_crc:08X}, calc=0x{calc_meta_crc:08X}")
		ok = False
	if signature_ok is False:
		messages.append("ECDSA signature mismatch")
		ok = False
	if trust_ok is False:
		messages.append("Trust-tag HMAC mismatch")
		ok = False
	if trust_ok is True:
		messages.append("Trust-tag verify OK")

	return ok, messages, key_id, fw_addr, flags


def relocate_flash_addresses(blob: bytes, link_origin: int, run_origin: int, window_size: int) -> bytes:
	"""Relocate absolute flash addresses in a raw firmware blob.

	This is a best-effort fix for firmware linked at one flash origin and programmed
	at another origin. Every 32-bit little-endian word within
	[link_origin, link_origin + window_size) is shifted by (run_origin - link_origin).
	"""
	if window_size <= 0:
		raise ValueError("window_size must be positive")

	delta = run_origin - link_origin
	start = link_origin
	end = link_origin + window_size
	out = bytearray(blob)

	for i in range(0, len(out) - 3, 4):
		word = struct.unpack_from("<I", out, i)[0]
		if start <= word < end:
			struct.pack_into("<I", out, i, (word + delta) & 0xFFFFFFFF)

	return bytes(out)


def _write_intel_hex(data: bytes, base_address: int, path: str) -> None:
	"""Write a flat binary blob as an Intel HEX file rooted at base_address."""

	def make_record(rec_type: int, address: int, payload: bytes) -> str:
		rec = bytes([len(payload), (address >> 8) & 0xFF, address & 0xFF, rec_type]) + payload
		checksum = (-(sum(rec))) & 0xFF
		return ":" + rec.hex().upper() + f"{checksum:02X}"

	row_size = 16
	current_upper = -1

	with open(path, "w", newline="\n") as f:
		for offset in range(0, len(data), row_size):
			abs_addr = base_address + offset
			upper = (abs_addr >> 16) & 0xFFFF

			if upper != current_upper:
				upper_bytes = bytes([(upper >> 8) & 0xFF, upper & 0xFF])
				f.write(make_record(4, 0, upper_bytes) + "\n")
				current_upper = upper

			chunk = data[offset:offset + row_size]
			f.write(make_record(0, abs_addr & 0xFFFF, chunk) + "\n")

		f.write(":00000001FF\n")


class STM32DFU:
	"""Minimal STM32 DFU (DfuSe-style) client over native USB control transfers."""

	# DFU class requests
	DFU_DETACH = 0
	DFU_DNLOAD = 1
	DFU_UPLOAD = 2
	DFU_GETSTATUS = 3
	DFU_CLRSTATUS = 4
	DFU_GETSTATE = 5
	DFU_ABORT = 6

	# DfuSe command payloads for DNLOAD block 0
	CMD_SET_ADDRESS_POINTER = 0x21
	CMD_ERASE = 0x41

	# DFU state machine values
	STATE_DFU_DNLOAD_SYNC = 3
	STATE_DFU_DNLOAD_BUSY = 4
	STATE_DFU_DNLOAD_IDLE = 5
	STATE_DFU_MANIFEST_SYNC = 6
	STATE_DFU_MANIFEST = 7
	STATE_DFU_MANIFEST_WAIT_RESET = 8
	STATE_DFU_UPLOAD_IDLE = 9
	STATE_DFU_ERROR = 10

	def __init__(self, vid=0x0483, pid=0xDF11, transfer_size=1024, timeout_ms=4000, libusb_dll=None):
		self.vid = vid
		self.pid = pid
		self.transfer_size = transfer_size
		self.timeout_ms = timeout_ms
		self.libusb_dll = libusb_dll
		self.dev = None
		self.intf = None
		self.backend = None

	def _get_backend(self):
		if self.backend is not None:
			return self.backend

		if self.libusb_dll:
			self.backend = usb.backend.libusb1.get_backend(find_library=lambda _: self.libusb_dll)
			return self.backend

		if libusb_package is not None:
			self.backend = usb.backend.libusb1.get_backend(find_library=libusb_package.find_library)
		else:
			self.backend = usb.backend.libusb1.get_backend()
		return self.backend

	def open(self):
		self.dev = usb.core.find(idVendor=self.vid, idProduct=self.pid, backend=self._get_backend())
		if self.dev is None:
			raise RuntimeError(f"DFU device not found: VID=0x{self.vid:04X}, PID=0x{self.pid:04X}")

		self.dev.set_configuration()
		cfg = self.dev.get_active_configuration()

		# Find DFU interface (Application Specific / DFU / DFU mode)
		for i in cfg:
			if i.bInterfaceClass == 0xFE and i.bInterfaceSubClass == 0x01 and i.bInterfaceProtocol == 0x02:
				self.intf = i
				break

		if self.intf is None:
			raise RuntimeError("No DFU interface found")

		try:
			if self.dev.is_kernel_driver_active(self.intf.bInterfaceNumber):
				self.dev.detach_kernel_driver(self.intf.bInterfaceNumber)
		except (NotImplementedError, usb.core.USBError):
			# Common on Windows where there is no kernel driver to detach.
			pass

		usb.util.claim_interface(self.dev, self.intf.bInterfaceNumber)
		self.clear_error_state()
		return self

	def close(self):
		if self.dev is not None and self.intf is not None:
			usb.util.release_interface(self.dev, self.intf.bInterfaceNumber)
		usb.util.dispose_resources(self.dev)
		self.dev = None
		self.intf = None

	def __enter__(self):
		return self.open()

	def __exit__(self, exc_type, exc, tb):
		self.close()

	def _ctrl_out(self, req, value, data=b""):
		return self.dev.ctrl_transfer(
			0x21,  # Host->Interface | Class
			req,
			value,
			self.intf.bInterfaceNumber,
			data,
			timeout=self.timeout_ms,
		)

	def _ctrl_in(self, req, value, length):
		return bytes(
			self.dev.ctrl_transfer(
				0xA1,  # Interface->Host | Class
				req,
				value,
				self.intf.bInterfaceNumber,
				length,
				timeout=self.timeout_ms,
			)
		)

	def get_state(self):
		return self._ctrl_in(self.DFU_GETSTATE, 0, 1)[0]

	def get_status(self):
		raw = self._ctrl_in(self.DFU_GETSTATUS, 0, 6)
		bw_poll_timeout_ms = raw[1] | (raw[2] << 8) | (raw[3] << 16)
		return {
			"status": raw[0],
			"poll_timeout_ms": bw_poll_timeout_ms,
			"state": raw[4],
			"iString": raw[5],
			"raw": raw,
		}

	def clear_status(self):
		self._ctrl_out(self.DFU_CLRSTATUS, 0, b"")

	def abort(self):
		self._ctrl_out(self.DFU_ABORT, 0, b"")

	def clear_error_state(self):
		# Try to recover from previous failed operations.
		for _ in range(3):
			st = self.get_status()
			if st["state"] != self.STATE_DFU_ERROR:
				return
			self.clear_status()
		st = self.get_status()
		if st["state"] == self.STATE_DFU_ERROR:
			raise RuntimeError(f"Device stuck in DFU_ERROR, status=0x{st['status']:02X}")

	def recover_idle(self):
		"""Best-effort move to dfuIDLE before a new command sequence."""
		for _ in range(4):
			st = self.get_status()
			state = st["state"]
			if state == self.STATE_DFU_ERROR:
				self.clear_status()
				continue
			if state in (self.STATE_DFU_DNLOAD_IDLE, self.STATE_DFU_UPLOAD_IDLE):
				self.abort()
				continue
			if state in (self.STATE_DFU_DNLOAD_SYNC, self.STATE_DFU_DNLOAD_BUSY,
						 self.STATE_DFU_MANIFEST_SYNC, self.STATE_DFU_MANIFEST):
				time.sleep(max(st["poll_timeout_ms"], 1) / 1000.0)
				continue
			if state == self.STATE_DFU_MANIFEST_WAIT_RESET:
				raise RuntimeError("Device entered MANIFEST_WAIT_RESET; re-enter DFU mode and retry")
			return

	def _wait_while_busy(self):
		while True:
			st = self.get_status()
			if st["state"] == self.STATE_DFU_ERROR:
				raise RuntimeError(f"DFU error: bStatus=0x{st['status']:02X}, raw={st['raw'].hex()}")

			if st["state"] in (self.STATE_DFU_DNLOAD_BUSY, self.STATE_DFU_DNLOAD_SYNC):
				time.sleep(max(st["poll_timeout_ms"], 1) / 1000.0)
				continue

			return st

	def _dnload(self, block_num, payload):
		self.recover_idle()
		try:
			self._ctrl_out(self.DFU_DNLOAD, block_num, payload)
		except usb.core.USBError as e:
			# Some stacks leave EP0 stalled after prior errors; recover and retry once.
			if getattr(e, "errno", None) == 32:
				self.recover_idle()
				self._ctrl_out(self.DFU_DNLOAD, block_num, payload)
			else:
				raise
		return self._wait_while_busy()

	def set_address_pointer(self, address):
		payload = bytes([self.CMD_SET_ADDRESS_POINTER]) + struct.pack("<I", address)
		self._dnload(0, payload)

	def erase_page(self, address):
		payload = bytes([self.CMD_ERASE]) + struct.pack("<I", address)
		self._dnload(0, payload)

	def mass_erase(self):
		# Supported by your bootloader patch via 1-byte DFU_CMD_ERASE payload.
		self._dnload(0, bytes([self.CMD_ERASE]))

	def read_memory(self, address, length):
		self.set_address_pointer(address)
		# STM32 DFU implementation accepts UPLOAD from dfuIDLE/uploadIDLE,
		# not from dfuDNLOAD-IDLE reached after SET_ADDRESS_POINTER.
		self.abort()
		out = bytearray()
		block = 2
		while len(out) < length:
			chunk = min(self.transfer_size, length - len(out))
			data = self._ctrl_in(self.DFU_UPLOAD, block, chunk)
			out.extend(data)
			if len(data) < chunk:
				break
			block += 1
		return bytes(out[:length])

	def write_memory(self, address, data, manifest=False):
		self.recover_idle()
		self.set_address_pointer(address)

		block = 2
		for offset in range(0, len(data), self.transfer_size):
			chunk = data[offset:offset + self.transfer_size]
			self._dnload(block, chunk)
			block += 1

		if manifest:
			# End DNLOAD transfer (Manifest phase trigger). On this bootloader
			# this can reset/leave DFU mode, so keep it optional.
			self._ctrl_out(self.DFU_DNLOAD, 0, b"")
			self._wait_while_busy()
		else:
			# Return to IDLE while keeping DFU mode active.
			self.abort()

	def manifest(self):
		"""Trigger DFU manifestation to leave DFU and run firmware.

		On many devices, USB disconnect/reset during this request is expected.
		"""
		self.recover_idle()
		self._ctrl_out(self.DFU_DNLOAD, 0, b"")
		try:
			return self._wait_while_busy()
		except usb.core.USBError:
			return None

	def device_info(self):
		"""Return basic USB descriptor information for the connected DFU device."""
		def _safe_get_string(index):
			if not index:
				return ""
			try:
				return usb.util.get_string(self.dev, index) or ""
			except usb.core.USBError:
				return ""

		return {
			"vid": self.dev.idVendor,
			"pid": self.dev.idProduct,
			"bcdDevice": self.dev.bcdDevice,
			"manufacturer": _safe_get_string(self.dev.iManufacturer),
			"product": _safe_get_string(self.dev.iProduct),
			"serial": _safe_get_string(self.dev.iSerialNumber),
			"dfu_interface": self.intf.bInterfaceNumber,
		}


def _parse_int(value):
	return int(value, 0)


def main():
	p = argparse.ArgumentParser(description="Native STM32 DFU test utility (PyUSB)")
	p.add_argument("--vid", type=_parse_int, default=0x0483)
	p.add_argument("--pid", type=_parse_int, default=0xDF11)
	p.add_argument("--xfer", type=int, default=1024, help="DFU transfer size")
	p.add_argument("--libusb-dll", default=None, help="Optional full path to libusb-1.0.dll")

	sub = p.add_subparsers(dest="cmd", required=True)

	e = sub.add_parser("erase", help="Erase one page at address")
	e.add_argument("address", type=_parse_int)

	me = sub.add_parser("mass-erase", help="Erase full application region")

	i = sub.add_parser("info", help="Print USB descriptor information for DFU device")

	gv = sub.add_parser("get-version", help="Read bootloader version string via USB DFU")

	rb = sub.add_parser("reboot", help="Reset the device from DFU mode")

	r = sub.add_parser("read", help="Read bytes from target memory")
	r.add_argument("address", type=_parse_int)
	r.add_argument("length", type=_parse_int)
	r.add_argument("outfile")

	w = sub.add_parser("write", help="Write binary file to target memory")
	w.add_argument("address", type=_parse_int)
	w.add_argument("infile")
	w.add_argument("--erase-pages", action="store_true", help="Erase touched pages before write")
	w.add_argument("--manifest", action="store_true", help="Send final zero-length DNLOAD (may reset/leave DFU)")

	v = sub.add_parser("verify", help="Read back memory and compare with binary file")
	v.add_argument("address", type=_parse_int)
	v.add_argument("infile")

	pk = sub.add_parser("pack-signed", help="Create distributable signed package (firmware.signed.bin)")
	pk.add_argument("infile")
	pk.add_argument("keyfile", help="Signing key file (PEM private key or raw 32-byte scalar)")
	pk.add_argument("outfile")
	pk.add_argument("--address", type=_parse_int, default=APP_ADDRESS_DEFAULT)
	pk.add_argument("--meta-address", type=_parse_int, default=META_ADDRESS_DEFAULT)
	pk.add_argument("--key-id", type=_parse_int, default=1)
	pk.add_argument("--link-origin", type=_parse_int, default=None,
				help="Original link address to relocate from (e.g. 0x08000000)")
	pk.add_argument("--run-origin", type=_parse_int, default=None,
				help="Runtime/program address to relocate to (defaults to --address)")
	pk.add_argument("--relocate-window", type=_parse_int, default=DEFAULT_RELOCATE_WINDOW,
				help="Address window size to relocate (default: 100K)")
	pk.add_argument("--trust-keyfile", default=None,
				help="Optional trust HMAC key file (raw 32-byte or 64-char hex)")

	vp = sub.add_parser("verify-package", help="Verify signed package integrity and metadata authenticity")
	vp.add_argument("packagefile")
	vp.add_argument("keyfile", help="Verification key (PEM public/private key, raw 64-byte x||y public key, or raw 32-byte private scalar)")
	vp.add_argument("--trust-keyfile", default=None,
				help="Optional trust HMAC key file to verify trust_tag")

	pp = sub.add_parser("program-package", help="Program firmware+metadata from signed package")
	pp.add_argument("packagefile")
	pp.add_argument("--manifest", action="store_true",
				help="Send final zero-length DNLOAD after successful write (may reset and run app)")

	s = sub.add_parser("sign-metadata", help="Create metadata block for firmware image")
	s.add_argument("infile")
	s.add_argument("keyfile", help="Signing key file (PEM private key or raw 32-byte scalar)")
	s.add_argument("outfile")
	s.add_argument("--address", type=_parse_int, default=APP_ADDRESS_DEFAULT)
	s.add_argument("--key-id", type=_parse_int, default=1)
	s.add_argument("--link-origin", type=_parse_int, default=None,
				help="Original link address to relocate from (e.g. 0x08000000)")
	s.add_argument("--run-origin", type=_parse_int, default=None,
				help="Runtime/program address to relocate to (defaults to --address)")
	s.add_argument("--relocate-window", type=_parse_int, default=DEFAULT_RELOCATE_WINDOW,
				help="Address window size to relocate (default: 100K)")
	s.add_argument("--trust-keyfile", default=None,
				help="Optional trust HMAC key file (raw 32-byte or 64-char hex)")

	vm = sub.add_parser("verify-metadata", help="Verify metadata blob against firmware/key")
	vm.add_argument("infile")
	vm.add_argument("keyfile", help="Verification key (PEM public/private key, raw 64-byte x||y public key, or raw 32-byte private scalar)")
	vm.add_argument("metafile")
	vm.add_argument("--link-origin", type=_parse_int, default=None,
				help="Original link address to relocate from (e.g. 0x08000000)")
	vm.add_argument("--run-origin", type=_parse_int, default=None,
				help="Runtime/program address to relocate to (defaults to metadata fw_address)")
	vm.add_argument("--relocate-window", type=_parse_int, default=DEFAULT_RELOCATE_WINDOW,
				help="Address window size to relocate (default: 100K)")
	vm.add_argument("--trust-keyfile", default=None,
				help="Optional trust HMAC key file to verify trust_tag")

	ps = sub.add_parser("program-signed", help="Program firmware and generated metadata in one step")
	ps.add_argument("infile")
	ps.add_argument("keyfile")
	ps.add_argument("--address", type=_parse_int, default=APP_ADDRESS_DEFAULT)
	ps.add_argument("--meta-address", type=_parse_int, default=META_ADDRESS_DEFAULT)
	ps.add_argument("--key-id", type=_parse_int, default=1)
	ps.add_argument("--link-origin", type=_parse_int, default=None,
				help="Original link address to relocate from (e.g. 0x08000000)")
	ps.add_argument("--run-origin", type=_parse_int, default=None,
				help="Runtime/program address to relocate to (defaults to --address)")
	ps.add_argument("--relocate-window", type=_parse_int, default=DEFAULT_RELOCATE_WINDOW,
				help="Address window size to relocate (default: 100K)")
	ps.add_argument("--trust-keyfile", default=None,
				help="Optional trust HMAC key file (raw 32-byte or 64-char hex)")
	ps.add_argument("--manifest", action="store_true",
				help="Send final zero-length DNLOAD after successful write (may reset and run app)")

	mp = sub.add_parser(
		"merge-production",
		help="Merge bootloader + signed package into a single flat binary (and optionally Intel HEX) for production flashing",
	)
	mp.add_argument("outfile", help="Output path for the merged flat binary (e.g. production.bin)")
	mp.add_argument("--bl", required=True, help="Bootloader binary file (e.g. lifu-transmitter-bl.bin)")
	mp.add_argument("--package", required=True,
				help="Signed firmware package produced by pack-signed (e.g. lifu-transmitter-fw.bin.signed.bin)")
	mp.add_argument("--base-address", type=_parse_int, default=0x08000000,
				help="Flash base address where bootloader is placed (default: 0x08000000)")
	mp.add_argument("--hex", action="store_true",
				help="Also write an Intel HEX file alongside the .bin (same path, .hex extension)")

	args = p.parse_args()

	if args.cmd == "sign-metadata":
		with open(args.infile, "rb") as f:
			fw = f.read()

		if args.link_origin is not None:
			run_origin = args.run_origin if args.run_origin is not None else args.address
			fw = relocate_flash_addresses(fw, args.link_origin, run_origin, args.relocate_window)
			print(f"Relocated image: 0x{args.link_origin:08X} -> 0x{run_origin:08X} (window {args.relocate_window} bytes)")

		with open(args.keyfile, "rb") as f:
			key = f.read()

		trust_key = None
		if args.trust_keyfile:
			with open(args.trust_keyfile, "rb") as f:
				trust_key = _load_trust_key(f.read())

		meta = build_metadata_blob(fw, key, args.address, args.key_id, trust_key)
		with open(args.outfile, "wb") as f:
			f.write(meta)
		print(f"Metadata written: {args.outfile} ({len(meta)} bytes)")
		if trust_key is None:
			print("Note: trust_tag not sealed (all zeros); bootloader will use slow ECDSA path on cold boot.")
		return

	if args.cmd == "verify-metadata":
		with open(args.infile, "rb") as f:
			fw = f.read()
		with open(args.keyfile, "rb") as f:
			key = f.read()
		with open(args.metafile, "rb") as f:
			meta_blob = f.read()

		(magic, version, flags, fw_addr, fw_len, fw_crc, key_id, signature, trust_tag, meta_crc) = parse_metadata_blob(meta_blob)

		if args.link_origin is not None:
			run_origin = args.run_origin if args.run_origin is not None else fw_addr
			fw = relocate_flash_addresses(fw, args.link_origin, run_origin, args.relocate_window)
			print(f"Relocated image for verify: 0x{args.link_origin:08X} -> 0x{run_origin:08X} (window {args.relocate_window} bytes)")
		elif args.run_origin is not None:
			raise SystemExit("--run-origin requires --link-origin")

		calc_meta_crc = stm32_crc32(meta_blob[: struct.calcsize(META_STRUCT_WITHOUT_CRC)])
		calc_fw_crc = stm32_crc32(fw)
		calc_fw_digest = hashlib.sha256(fw).digest()
		signature_ok = _ecdsa_p256_verify_raw(key, calc_fw_digest, signature)
		trust_ok = None

		if args.trust_keyfile:
			with open(args.trust_keyfile, "rb") as f:
				trust_key = _load_trust_key(f.read())
			msg = struct.pack(
				"<IHHIIII64s",
				magic,
				version,
				flags,
				fw_addr,
				fw_len,
				fw_crc,
				key_id,
				signature,
			)
			trust_ok = hmac.compare_digest(hmac.new(trust_key, msg, hashlib.sha256).digest(), trust_tag)

		ok = True
		if magic != META_MAGIC or version != META_VERSION:
			print("Metadata magic/version mismatch")
			ok = False
		if flags != META_FLAGS_SIGNATURE_REQUIRED:
			print(f"Metadata flags mismatch: meta=0x{flags:04X}, expected=0x{META_FLAGS_SIGNATURE_REQUIRED:04X}")
			ok = False
		if fw_len != len(fw):
			print(f"Firmware length mismatch: meta={fw_len}, file={len(fw)}")
			ok = False
		if fw_crc != calc_fw_crc:
			print(f"Firmware CRC mismatch: meta=0x{fw_crc:08X}, calc=0x{calc_fw_crc:08X}")
			ok = False
		if meta_crc != calc_meta_crc:
			print(f"Metadata CRC mismatch: meta=0x{meta_crc:08X}, calc=0x{calc_meta_crc:08X}")
			ok = False
		if signature_ok is False:
			print("ECDSA signature mismatch")
			ok = False
		if trust_ok is False:
			print("Trust-tag HMAC mismatch")
			ok = False

		if not ok:
			raise SystemExit(2)
		if trust_ok is True:
			print("Trust-tag verify OK")
		print(f"Metadata verify OK (key_id={key_id}, fw_addr=0x{fw_addr:08X}, flags=0x{flags:04X})")
		return

	if args.cmd == "pack-signed":
		with open(args.infile, "rb") as f:
			fw = f.read()

		if args.link_origin is not None:
			run_origin = args.run_origin if args.run_origin is not None else args.address
			fw = relocate_flash_addresses(fw, args.link_origin, run_origin, args.relocate_window)
			print(f"Relocated image: 0x{args.link_origin:08X} -> 0x{run_origin:08X} (window {args.relocate_window} bytes)")

		with open(args.keyfile, "rb") as f:
			key = f.read()

		trust_key = None
		if args.trust_keyfile:
			with open(args.trust_keyfile, "rb") as f:
				trust_key = _load_trust_key(f.read())

		meta = build_metadata_blob(fw, key, args.address, args.key_id, trust_key)
		pkg = build_signed_package(fw, meta, args.address, args.meta_address)

		with open(args.outfile, "wb") as f:
			f.write(pkg)

		print(f"Signed package written: {args.outfile} ({len(pkg)} bytes)")
		print(f"  firmware bytes: {len(fw)} at 0x{args.address:08X}")
		print(f"  metadata bytes: {len(meta)} at 0x{args.meta_address:08X}")
		if trust_key is None:
			print("Note: trust_tag not sealed (all zeros); bootloader will use slow ECDSA path on cold boot.")
		return

	if args.cmd == "verify-package":
		with open(args.packagefile, "rb") as f:
			pkg_blob = f.read()
		pkg = parse_signed_package(pkg_blob)

		with open(args.keyfile, "rb") as f:
			key = f.read()

		trust_key = None
		if args.trust_keyfile:
			with open(args.trust_keyfile, "rb") as f:
				trust_key = _load_trust_key(f.read())

		ok, messages, key_id, fw_addr, flags = verify_metadata_against_firmware(
			pkg["fw"], key, pkg["meta"], trust_key
		)

		for line in messages:
			print(line)

		if fw_addr != pkg["fw_address"]:
			print(f"Package firmware address mismatch: pkg=0x{pkg['fw_address']:08X}, meta=0x{fw_addr:08X}")
			ok = False

		if not ok:
			raise SystemExit(2)

		print(
			f"Package verify OK (key_id={key_id}, fw_addr=0x{fw_addr:08X}, "
			f"meta_addr=0x{pkg['meta_address']:08X}, flags=0x{flags:04X})"
		)
		return

	if args.cmd == "merge-production":
		with open(args.bl, "rb") as f:
			bl_data = f.read()

		with open(args.package, "rb") as f:
			pkg = parse_signed_package(f.read())

		fw = pkg["fw"]
		meta = pkg["meta"]
		fw_address = pkg["fw_address"]
		meta_address = pkg["meta_address"]
		base = args.base_address

		# Sanity checks
		if fw_address < base:
			raise SystemExit(f"Firmware address 0x{fw_address:08X} is below base 0x{base:08X}")
		if meta_address < base:
			raise SystemExit(f"Metadata address 0x{meta_address:08X} is below base 0x{base:08X}")
		bl_end = base + len(bl_data)
		if bl_end > meta_address:
			raise SystemExit(
				f"Bootloader ({len(bl_data)} bytes) ends at 0x{bl_end:08X}, "
				f"which overlaps metadata region at 0x{meta_address:08X}"
			)
		if meta_address + len(meta) > fw_address:
			raise SystemExit(
				f"Metadata region (0x{meta_address:08X}+{len(meta)}) overlaps firmware at 0x{fw_address:08X}"
			)

		# Build flat image: 0xFF-filled from base to end of firmware
		image_size = (fw_address + len(fw)) - base
		image = bytearray(b"\xFF" * image_size)

		image[0 : len(bl_data)] = bl_data
		meta_off = meta_address - base
		image[meta_off : meta_off + len(meta)] = meta
		fw_off = fw_address - base
		image[fw_off : fw_off + len(fw)] = fw

		with open(args.outfile, "wb") as f:
			f.write(bytes(image))

		print(f"Production image written: {args.outfile} ({len(image)} bytes / {len(image) / 1024:.1f} KB)")
		print(f"  Base address : 0x{base:08X}")
		print(f"  Bootloader   : 0x{base:08X}  ({len(bl_data)} bytes)")
		print(f"  Metadata     : 0x{meta_address:08X}  ({len(meta)} bytes)")
		print(f"  Firmware     : 0x{fw_address:08X}  ({len(fw)} bytes)")
		print()
		print("Flash with OpenOCD:")
		print(f"  openocd -f interface/stlink.cfg -f target/stm32l4x.cfg \\")
		print(f'          -c "program {args.outfile} 0x{base:08X} verify reset exit"')
		print()
		print("Flash with STM32CubeProgrammer CLI:")
		print(f"  STM32_Programmer_CLI -c port=SWD -d {args.outfile} 0x{base:08X} -v -rst")

		if args.hex:
			hex_path = (
				args.outfile.rsplit(".", 1)[0] + ".hex"
				if "." in args.outfile
				else args.outfile + ".hex"
			)
			_write_intel_hex(bytes(image), base, hex_path)
			print()
			print(f"Intel HEX written: {hex_path}")
			print("Flash HEX with STM32CubeProgrammer CLI (no base address needed):")
			print(f"  STM32_Programmer_CLI -c port=SWD -d {hex_path} -v -rst")
		return

	with STM32DFU(vid=args.vid, pid=args.pid, transfer_size=args.xfer, libusb_dll=args.libusb_dll) as dfu:
		if args.cmd == "erase":
			dfu.erase_page(args.address)
			print(f"Erased page at 0x{args.address:08X}")
		elif args.cmd == "mass-erase":
			dfu.mass_erase()
			print("Mass erase command sent")
		elif args.cmd == "info":
			info = dfu.device_info()
			print(f"VID:PID      0x{info['vid']:04X}:0x{info['pid']:04X}")
			print(f"bcdDevice:   0x{info['bcdDevice']:04X}")
			print(f"Manufacturer: {info['manufacturer']}")
			print(f"Product:      {info['product']}")
			print(f"Serial:       {info['serial']}")
			print(f"DFU intf #:   {info['dfu_interface']}")
		elif args.cmd == "get-version":
			raw = dfu.read_memory(DFU_VERSION_VIRT_ADDR, DFU_VERSION_READ_LEN)
			version = raw.split(b"\x00")[0].decode("ascii", errors="replace")
			if not version:
				print("Version string is empty (bootloader may not support this command)")
			else:
				print(f"Bootloader version: {version}")
		elif args.cmd == "reboot":
			try:
				dfu.write_memory(DFU_RESET_VIRT_ADDR, b'\x00' * 8)
			except usb.core.USBError:
				pass  # device reset before response — expected
			print("Reset command sent. Device is rebooting.")
		elif args.cmd == "read":
			data = dfu.read_memory(args.address, args.length)
			with open(args.outfile, "wb") as f:
				f.write(data)
			print(f"Read {len(data)} bytes from 0x{args.address:08X} -> {args.outfile}")
		elif args.cmd == "write":
			with open(args.infile, "rb") as f:
				blob = f.read()

			if args.erase_pages and blob:
				page_size = 2048
				first = args.address & ~(page_size - 1)
				last_addr = args.address + len(blob) - 1
				last = last_addr & ~(page_size - 1)
				num_pages = int((last - first) / page_size) + 1
				for i in range(num_pages):
					dfu.erase_page(first + i * page_size)

			dfu.write_memory(args.address, blob, manifest=args.manifest)
			print(f"Wrote {len(blob)} bytes to 0x{args.address:08X}")
		elif args.cmd == "verify":
			with open(args.infile, "rb") as f:
				expected = f.read()

			actual = dfu.read_memory(args.address, len(expected))

			if actual == expected:
				print(f"Verify OK: {len(expected)} bytes at 0x{args.address:08X}")
				return

			mismatch_index = next((i for i, (a, b) in enumerate(zip(actual, expected)) if a != b), None)
			if mismatch_index is None and len(actual) != len(expected):
				mismatch_index = min(len(actual), len(expected))

			print(f"Verify FAILED at offset 0x{mismatch_index:08X} (addr 0x{args.address + mismatch_index:08X})")
			if mismatch_index < len(expected):
				print(f"  expected: 0x{expected[mismatch_index]:02X}")
			if mismatch_index < len(actual):
				print(f"  actual  : 0x{actual[mismatch_index]:02X}")
			raise SystemExit(2)
		elif args.cmd == "program-signed":
			with open(args.infile, "rb") as f:
				fw = f.read()

			if args.link_origin is not None:
				run_origin = args.run_origin if args.run_origin is not None else args.address
				fw = relocate_flash_addresses(fw, args.link_origin, run_origin, args.relocate_window)
				print(f"Relocated image: 0x{args.link_origin:08X} -> 0x{run_origin:08X} (window {args.relocate_window} bytes)")

			with open(args.keyfile, "rb") as f:
				key = f.read()

			trust_key = None
			if args.trust_keyfile:
				with open(args.trust_keyfile, "rb") as f:
					trust_key = _load_trust_key(f.read())

			meta = build_metadata_blob(fw, key, args.address, args.key_id, trust_key)

			if fw:
				page_size = 2048
				first = args.address & ~(page_size - 1)
				last_addr = args.address + len(fw) - 1
				last = last_addr & ~(page_size - 1)
				num_pages = int((last - first) / page_size) + 1
				for i in range(num_pages):
					dfu.erase_page(first + i * page_size)

			# Metadata occupies exactly one 2 KB page at 0x08006800.
			dfu.erase_page(args.meta_address)
			dfu.write_memory(args.address, fw)
			dfu.write_memory(args.meta_address, meta)

			# Quick readback verification of metadata bytes.
			meta_rb = dfu.read_memory(args.meta_address, len(meta))
			if meta_rb != meta:
				print("Metadata readback mismatch")
				raise SystemExit(2)
			print(f"Programmed signed firmware ({len(fw)} bytes) and metadata at 0x{args.meta_address:08X}")
			if trust_key is None:
				print("Note: trust_tag not sealed (all zeros); bootloader will use slow ECDSA path on cold boot.")

			if args.manifest:
				dfu.manifest()
				print("Manifest sent: device should leave DFU and jump to application")
		elif args.cmd == "program-package":
			with open(args.packagefile, "rb") as f:
				pkg_blob = f.read()
			pkg = parse_signed_package(pkg_blob)
			fw = pkg["fw"]
			meta = pkg["meta"]
			fw_addr = pkg["fw_address"]
			meta_addr = pkg["meta_address"]

			if fw:
				page_size = 2048
				first = fw_addr & ~(page_size - 1)
				last_addr = fw_addr + len(fw) - 1
				last = last_addr & ~(page_size - 1)
				num_pages = int((last - first) / page_size) + 1
				for i in range(num_pages):
					dfu.erase_page(first + i * page_size)

			dfu.erase_page(meta_addr)
			dfu.write_memory(fw_addr, fw)
			dfu.write_memory(meta_addr, meta)

			meta_rb = dfu.read_memory(meta_addr, len(meta))
			if meta_rb != meta:
				print("Metadata readback mismatch")
				raise SystemExit(2)

			print(
				f"Programmed package firmware ({len(fw)} bytes) at 0x{fw_addr:08X} "
				f"and metadata ({len(meta)} bytes) at 0x{meta_addr:08X}"
			)

			if args.manifest:
				dfu.manifest()
				print("Manifest sent: device should leave DFU and jump to application")


if __name__ == "__main__":
	main()
