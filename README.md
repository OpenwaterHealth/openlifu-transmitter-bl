# LIFU Transmitter Bootloader

Lightweight bootloader for the LIFU transmitter (STM32L4 series).

## Overview

This repository contains a compact bootloader and supporting tooling used to build, flash, and test firmware for the LIFU transmitter hardware (STM32L443 family). It includes board-specific linker script and startup files, HAL-based source, crypto utilities, and packaging for DFU/USB support.

## Key features

- Secure boot with ECDSA P-256 signature and HMAC-SHA256 trust-tag verification
- Persistent fault-tolerant boot state using RTC backup registers (survives watchdog and soft resets)
- Automatic DFU fallback after two consecutive application boot failures
- USB DFU firmware update over USB FS (STM32 USB Device Library)
- I2C slave DFU fallback for transmitters without USB connectivity (daisy-chain topology)
- CRC-32 guarded firmware metadata page separate from the application image
- Auth cache avoids full re-verification on every warm boot

## Hardware target

Target MCU: **STM32L443RCIx** — 256 KB Flash, 64 KB RAM (see `startup_stm32l443xx.s` and `STM32L443XX_FLASH.ld`).

---

## Architecture

### Flash memory layout

The 256 KB Flash is split into four fixed regions:

| Region      | Base address   | Size   | Contents                                       |
|-------------|----------------|--------|------------------------------------------------|
| Bootloader  | `0x08000000`   | 62 KB  | This bootloader binary                         |
| Metadata    | `0x0800F800`   | 2 KB   | `fw_metadata_t` struct (magic, CRC, signature) |
| Application | `0x08010000`   | 190 KB | User application image                         |
| User Config | `0x0803F800`   | 2 KB   | Persistent app config (not writable via DFU)   |

The bootloader is linked at `0x08000000` with a 62 KB FLASH region (see `STM32L443XX_FLASH.ld`). The USB DFU interface exposes only the metadata + application region (`@Firmware/0x0800F800/1*2Kg,190*2Kg`) so the bootloader itself and the user config page cannot be overwritten over USB.

### Boot decision flow

On each power-on or reset the bootloader runs through the following checks before deciding whether to launch the application or stay in DFU mode:

```
Reset / Power-on
      │
      ▼
HAL + peripheral init
      │
      ▼
Read & clear RCC reset flags  ──►  Persist to RTC backup registers
      │
      ▼
bl_bootstate_init()           ──►  Validate BKP0R signature 'OWBL'
                                   (initialise registers on cold start)
      │
      ▼
bl_clear_boot_state_cold()    ──►  Clear BOOT_IN_PROGRESS if POR/PIN reset
      │
      ▼
bl_app_stack_pointer_sane()   ──►  Check SP is in SRAM range 0x2000xxxx
      │
      ▼
bl_app_reset_vector_sane()    ──►  Check Reset_Handler is in app Flash range
                                   and has Thumb bit set
      │
      ▼
firmware_metadata_valid()     ──►  ① meta_crc32 self-check
  (if SP and RV sane)              ② fw_crc32 vs actual image
                                   ③ trust_tag HMAC-SHA256 verify
                                   ④ ECDSA P-256 signature verify
                                      (skipped if FW_META_FLAG_SIGNATURE_REQUIRED
                                       not set in flags field)
                                   ⑤ auth cache shortcut on warm boot
      │
      ▼
bl_should_enter_dfu()         ──►  Force DFU if any of:
                                    • BKP1R == 'DFU!' magic
                                    • fail_count >= BL_BOOT_FAIL_THRESHOLD (2)
                                    • IWDG/WWDG reset with BOOT_IN_PROGRESS set
                                    • meta_valid == 0
      │
      ├─── DFU ───► MX_USB_DEVICE_Init() → USB DFU loop
      │                                     heartbeat LED toggle (800 ms)
      │                                     IWDG refresh
      │
      └─── Boot ──► bl_mark_boot_in_progress()
                    MX_IWDG_Init()
                    jump_to_application(0x08010000)
                      • disable IRQs
                      • deinit RCC → HSI
                      • clear NVIC
                      • set VTOR = 0x08010000
                      • set MSP from app vector table[0]
                      • branch to app vector table[1] (Reset_Handler)
```

If the application boots successfully it is expected to write `BOOT_OK` into the RTC backup registers and clear `BOOT_IN_PROGRESS`. If the IWDG fires before that (hung application), the watchdog reset increments the fail counter. After two failures the bootloader enters DFU mode automatically.

### Firmware metadata (`fw_metadata_t`)

Stored at `0x0800F800`, one 2 KB Flash page:

| Field         | Type       | Description                                               |
|---------------|------------|-----------------------------------------------------------|
| `magic`       | `uint32_t` | Must be `0x314D4657` (`'WFM1'`)                           |
| `version`     | `uint16_t` | Metadata format version (currently `3`)                   |
| `flags`       | `uint16_t` | Bit 0 = `SIGNATURE_REQUIRED`                              |
| `fw_address`  | `uint32_t` | Application start address (`0x08010000`)                  |
| `fw_length`   | `uint32_t` | Application image size in bytes                           |
| `fw_crc32`    | `uint32_t` | CRC-32 of the application image                           |
| `key_id`      | `uint32_t` | Identifies which provisioned public key to use            |
| `signature`   | `uint8_t[64]` | ECDSA P-256 signature over the image                   |
| `trust_tag`   | `uint8_t[32]` | HMAC-SHA256 of metadata fields up to (not including) this field |
| `meta_crc32`  | `uint32_t` | CRC-32 of all preceding metadata fields                   |

### Trust and security model

**ECDSA signature (uECC)**
- Curve: P-256 (via the bundled `uECC` library in `Core/Src/uECC.c`).
- The signing private key is held by the release tooling. Only the corresponding public key(s) are stored in the bootloader (`g_bl_pubkeys[]` in `bl_trust.h`).
- Multiple public keys are supported; the `key_id` field in metadata selects the correct one.
- Signature verification uses constant-time comparison (`bl_consttime_equal`) to prevent timing side-channels.

**HMAC-SHA256 trust tag**
- Computed over the entire metadata struct up to (but not including) the `trust_tag` field.
- Keyed with a 32-byte device secret (`g_bl_trust_hmac_key` in `bl_trust.h`).
- Provides a second, symmetric layer of integrity: an attacker who can craft a valid ECDSA signature still needs the device secret to pass the trust tag check.

**Auth cache**
- On the first successful full verification the firmware CRC is stored XOR-obfuscated in RTC `BKP4R`.
- On subsequent warm boots (non-POR), if the stored value matches the current `fw_crc32`, full ECDSA re-verification is skipped.
- The cache is cleared on any failed verification or when new firmware is written.

**Persistent boot state (RTC backup registers)**

State survives `NVIC_SystemReset()` and watchdog resets because it is in the RTC backup domain, not `.noinit` RAM.

| Register | Purpose                                                  |
|----------|----------------------------------------------------------|
| `BKP0R`  | Signature (`0x4F57424C` / `'OWBL'`); absent = cold start |
| `BKP1R`  | DFU request magic (`0x21554644` / `'DFU!'`)              |
| `BKP2R`  | State flags + fail counter (bits 15:8)                   |
| `BKP3R`  | CRC of last rejected firmware image                      |
| `BKP4R`  | Auth cache (CRC XOR `0xA5964C3D`)                        |

### DFU mode

When DFU mode is active the device enumerates over USB as a standard DFU device. The STM32 USB Device Library DFU class is used with the flash interface implemented in `USB_DEVICE/App/usbd_dfu_if.c`.

- **Writable region:** metadata page + 190 application pages (starts at `0x0800F800`); the user config page at `0x0803F800` is outside this range and is not writable via DFU
- **Special erase-all command:** writing to address `0xFFFFFFFF` erases both regions
- **Erase/program timing:** 50 ms each (conservative, HAL Flash driver is used)
- The IWDG is refreshed by the DFU idle loop to keep the device alive during long USB transfers

To request DFU mode programmatically from the running application, write the magic value `0x21554644` (`'DFU!'`) to RTC `BKP1R` and then call `NVIC_SystemReset()`. The bootloader will detect the magic on the next boot and enter USB DFU mode.

### I2C DFU mode (no USB host)

Transmitters not directly connected to a USB host receive firmware updates over I2C, relayed by the upstream transmitter in the chain.

**Detection and fallback**

After entering DFU mode the bootloader brings up the USB device stack and waits up to 1.5 s for a host to enumerate (addressed/configured state). If no USB host is detected within that window:

1. The USB peripheral is torn down (`MX_USB_DEVICE_DeInit`).
2. I2C1 is reconfigured as a 7-bit slave at address `0x42` (`I2C_DFU_SLAVE_ADDR`).
3. The main loop calls `I2C_DFU_Process()` continuously instead of the USB DFU loop.
4. The heartbeat LED toggles at ~5 Hz (200 ms period) to distinguish this mode from USB DFU (800 ms).

**Chain topology**

```
USB host
   │  (USB DFU)
   ▼
Transmitter 0 (USB-connected, I2C master)
   │  I2C1  SCL=PB6 / SDA=PB7
   ▼
Transmitter 1 (no USB, I2C slave @ 0x42)   ← I2C DFU mode
   │  (relay, future extension)
   ▼
  ...
```

The upstream transmitter's application firmware reads DFU packets from the USB host and relays them to the downstream slave over I2C.

**I2C DFU protocol**

Every DFU exchange consists of two separate I2C transactions:

1. **WRITE** (master → slave): command byte, optional 4-byte target address (LE), optional 2-byte length (LE), optional data payload.
2. **READ** (master ← slave): 1-byte status + 1-byte DFU state (plus version string for `GETVERSION`).

If the status byte is `BUSY` (`0x01`) the flash operation is still running; the master must retry the read after a short delay.

| Command         | Byte | Description                                                   |
|-----------------|------|---------------------------------------------------------------|
| `DNLOAD`        | 0x01 | Write `len` bytes of firmware to `addr`                       |
| `ERASE`         | 0x02 | Erase flash page at `addr`; `0xFFFFFFFF` erases all app pages |
| `GETSTATUS`     | 0x03 | Query status and DFU state (no payload)                       |
| `MANIFEST`      | 0x04 | Finalise download — lock flash after all pages written        |
| `RESET`         | 0x05 | Reset the device                                              |
| `GETVERSION`    | 0x06 | Return 2-byte header + 32-byte null-padded version string     |

**Writable region and constraints**

- Same writable range as USB DFU: metadata page (`0x0800F800`) + 190 application pages.
- Maximum payload per `DNLOAD` transaction: 2048 bytes (`I2C_DFU_MAX_XFER_SIZE`).
- Flash erase/program is executed in the main loop (`I2C_DFU_Process`), not inside ISR callbacks, so IWDG can be refreshed during long full-erase sequences.
- The IWDG is refreshed on every main-loop iteration to prevent a reset during slow transfers.

---

## Requirements

- CMake 3.20+ (for presets)
- Ninja (recommended)
- ARM cross toolchain (e.g. `gcc-arm-none-eabi`)
- OpenOCD (for flashing)
- Python 3 (for test utilities in `test/`)

## Quickstart — build and flash

Clone the repo and use the provided CMake presets.

Configure (Debug):

```bash
cmake --preset Debug
```

Build (Debug):

```bash
cmake --build build/Debug --config Debug --target all -j 10
```

Flash (Debug) with OpenOCD:

```bash
openocd -f interface/stlink.cfg -f target/stm32l4x.cfg -c "program build/Debug/lifu-transmitter-bl.hex reset exit"
```

Alternatively, use the VS Code tasks shipped with the workspace: `CMake: Build (Debug)`, `Flash Firmware (Debug)`.

## Build (Release)

```bash
cmake --preset Release
cmake --build build/Release --config Release --target all -j 10
```

Flash (Release):

```bash
openocd -f interface/stlink.cfg -f target/stm32l4x.cfg -c "program build/Release/lifu-transmitter-bl.hex reset exit"
```

## Testing & utilities

- `test/dfu-test.py` — USB DFU test helper (requires Python and pyserial or related deps).
- `test/dfu-i2c-test.py` — I2C DFU test helper for downstream transmitters without USB.
- `test/dfu-signing.py` — create a signed firmware package from an app binary already linked for `0x08010000` (no relocation).
- `test/generate_keys.py` — helper to create test keys for signing/verifying images.

Create a signed package for DFU (`program-package`):

```bash
python test/dfu-signing.py \
      <path-to-app-bin> \
      test/keys/fw_signing_key.pem \
      --address 0x08010000 \
      --meta-address 0x0800F800 \
      --trust-keyfile test/keys/boot_trust_hmac_key.bin
```

Then flash it:

```bash
python test/dfu-test.py --libusb-dll test/libusb-1.0.29/VS2022/MS64/dll/libusb-1.0.dll \
      program-package <path-to-signed-bin> --manifest
```

Install Python test requirements:

```bash
python -m pip install -r test/requirements.txt
```

## Directory layout (high level)

- `Core/` — main application and bootloader source and headers
- `Drivers/` — CMSIS and HAL drivers
- `USB_DEVICE/` — USB DFU descriptors and interface
- `test/` — test scripts and key generation helpers
- `build/` — CMake build output (generated)

## Development notes

- The project uses `CMakePresets.json` for consistent builds across environments.
- Use the included `cmake/gcc-arm-none-eabi.cmake` toolchain file when creating custom builds.
- Generated headers (e.g. `generated/version.h`) are produced during configure/build.

## Contributing

Contributions are welcome. Please follow the repository `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`.

Before submitting a PR, ensure that:

- The project builds in at least the Debug preset
- Any new C files are added to the appropriate CMake targets
- Tests (where applicable) are added to `test/`

## License

See the repository root for licensing information.

## Contact

For questions, open an issue or contact the maintainers listed in the `CONTRIBUTING.md`.
