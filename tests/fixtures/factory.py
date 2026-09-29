"""Synthetic package generator for testing.

Generates minimal valid APKs, APKS bundles, XAPK bundles, split APK directories,
and malformed test files without requiring external Android build tools or proprietary APKs.
"""

from __future__ import annotations

import datetime
import json
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

__all__ = [
    "create_split_apk_dir",
    "create_synthetic_apk",
    "create_synthetic_apks",
    "create_synthetic_xapk",
    "generate_test_pkcs7_cert",
]


def generate_test_pkcs7_cert(
    common_name: str = "APKForge Test",
    organization: str = "APKForge",
) -> bytes:
    """Generate a self-signed PKCS#7 DER-encoded certificate structure."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, organization),
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(123456789)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    builder = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"APKForge Test Signature")
        .add_signer(cert, key, hashes.SHA256())
    )
    return builder.sign(Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])


def create_synthetic_apk(
    output_path: Path,
    *,
    package_name: str = "com.apkforge.testapp",
    version_name: str = "1.0.0",
    version_code: int = 100,
    min_sdk: int = 26,
    target_sdk: int = 34,
    dex_count: int = 1,
    native_abis: list[str] | None = None,
    include_cert: bool = True,
    extra_files: dict[str, bytes] | None = None,
) -> Path:
    """Create a minimal synthetic APK archive at *output_path*."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    manifest_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}"
    android:versionCode="{version_code}"
    android:versionName="{version_name}">
    <uses-sdk android:minSdkVersion="{min_sdk}" android:targetSdkVersion="{target_sdk}" />
    <application android:label="Synthetic Test App" android:debuggable="false">
        <activity android:name=".MainActivity" />
    </application>
</manifest>""".encode()

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml)

        # DEX files
        for i in range(1, dex_count + 1):
            name = "classes.dex" if i == 1 else f"classes{i}.dex"
            zf.writestr(name, b"dex\n035\x00" + b"\x00" * 64 + f"synthetic_dex_{i}".encode())

        # Native libraries
        if native_abis:
            for abi in native_abis:
                zf.writestr(
                    f"lib/{abi}/libsample.so",
                    b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32 + f"libsample_{abi}".encode(),
                )

        # Resources
        zf.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 32)
        zf.writestr("res/layout/activity_main.xml", b"<LinearLayout />")

        # Certificate
        if include_cert:
            cert_der = generate_test_pkcs7_cert()
            zf.writestr("META-INF/CERT.RSA", cert_der)
            sf_content = b"Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: abc\r\n"
            zf.writestr("META-INF/CERT.SF", sf_content)
            mf_content = b"Manifest-Version: 1.0\r\nCreated-By: APKForge Test\r\n"
            zf.writestr("META-INF/MANIFEST.MF", mf_content)

        # Extra files
        if extra_files:
            for entry_name, content in extra_files.items():
                zf.writestr(entry_name, content)

    return output_path


def create_synthetic_apks(
    output_path: Path,
    *,
    package_name: str = "com.apkforge.splitapp",
    version_code: int = 200,
) -> Path:
    """Create a synthetic .apks container holding base and configuration splits."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    base_apk = output_path.parent / "temp_base.apk"
    config_arm = output_path.parent / "temp_config_arm.apk"
    config_en = output_path.parent / "temp_config_en.apk"

    create_synthetic_apk(
        base_apk,
        package_name=package_name,
        version_code=version_code,
        dex_count=2,
    )
    create_synthetic_apk(
        config_arm,
        package_name=package_name,
        version_code=version_code,
        dex_count=0,
        native_abis=["arm64-v8a"],
    )
    create_synthetic_apk(
        config_en,
        package_name=package_name,
        version_code=version_code,
        dex_count=0,
    )

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(base_apk, "splits/base-master.apk")
        zf.write(config_arm, "splits/config.arm64_v8a.apk")
        zf.write(config_en, "splits/config.en.apk")
        zf.writestr("toc.pb", b"\x08\x01\x12\x05table")

    base_apk.unlink(missing_ok=True)
    config_arm.unlink(missing_ok=True)
    config_en.unlink(missing_ok=True)
    return output_path


def create_synthetic_xapk(
    output_path: Path,
    *,
    package_name: str = "com.apkforge.xapkapp",
    version_name: str = "2.1.0",
    version_code: int = 210,
) -> Path:
    """Create a synthetic .xapk container holding manifest.json and APKs."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    base_apk = output_path.parent / f"temp_{package_name}.apk"
    config_apk = output_path.parent / "temp_config_arm64.apk"

    create_synthetic_apk(
        base_apk,
        package_name=package_name,
        version_name=version_name,
        version_code=version_code,
        dex_count=1,
    )
    create_synthetic_apk(
        config_apk,
        package_name=package_name,
        version_name=version_name,
        version_code=version_code,
        dex_count=0,
        native_abis=["arm64-v8a"],
    )

    manifest_json = {
        "xapk_version": 1,
        "package_name": package_name,
        "name": "XAPK Test App",
        "version_code": version_code,
        "version_name": version_name,
        "min_sdk_version": 24,
        "target_sdk_version": 34,
        "split_apks": [
            {"file": f"{package_name}.apk", "id": "base"},
            {"file": "config.arm64_v8a.apk", "id": "config.arm64_v8a"},
        ],
    }

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest_json, indent=2))
        zf.write(base_apk, f"{package_name}.apk")
        zf.write(config_apk, "config.arm64_v8a.apk")

    base_apk.unlink(missing_ok=True)
    config_apk.unlink(missing_ok=True)
    return output_path


def create_split_apk_dir(
    dir_path: Path,
    *,
    package_name: str = "com.apkforge.splitdir",
    version_code: int = 300,
) -> Path:
    """Create a directory containing base and split APKs."""
    dir_path = Path(dir_path)
    dir_path.mkdir(parents=True, exist_ok=True)

    create_synthetic_apk(
        dir_path / "base.apk",
        package_name=package_name,
        version_code=version_code,
        dex_count=2,
    )
    create_synthetic_apk(
        dir_path / "config.arm64_v8a.apk",
        package_name=package_name,
        version_code=version_code,
        dex_count=0,
        native_abis=["arm64-v8a"],
    )
    create_synthetic_apk(
        dir_path / "config.en.apk",
        package_name=package_name,
        version_code=version_code,
        dex_count=0,
    )
    create_synthetic_apk(
        dir_path / "feature_camera.apk",
        package_name=package_name,
        version_code=version_code,
        dex_count=1,
    )
    return dir_path
