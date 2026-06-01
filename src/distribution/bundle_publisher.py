"""
OPA bundle builder and publisher — packages Rego policies into OPA bundles,
uploads to S3, and notifies OPA instances to reload.
"""
from __future__ import annotations
import hashlib
import logging
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Optional
import boto3
import httpx

log = logging.getLogger(__name__)


class BundlePublisher:
    def __init__(self, opa_url: str, s3_bucket: str, session: Optional[boto3.Session] = None) -> None:
        self._opa_url = opa_url.rstrip("/")
        self._bucket = s3_bucket
        self._s3 = (session or boto3.Session()).client("s3")
        self._http = httpx.Client(timeout=30)

    def build_bundle(self, policy_dir: str | Path, output_path: str | Path) -> Path:
        policy_dir = Path(policy_dir)
        output_path = Path(output_path)
        if not shutil.which("opa"):
            raise RuntimeError("'opa' CLI not found in PATH")
        cmd = ["opa", "build", str(policy_dir), "--output", str(output_path), "--bundle"]
        log.info("Building OPA bundle: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"opa build failed:\n{result.stderr}")
        log.info("Bundle built: %s (%d bytes)", output_path, output_path.stat().st_size)
        return output_path

    def build_bundle_manual(self, policy_dir: str | Path, output_path: str | Path) -> Path:
        """Fallback bundle builder using Python tarfile (no opa CLI required)."""
        policy_dir = Path(policy_dir)
        output_path = Path(output_path)
        with tarfile.open(output_path, "w:gz") as tar:
            for rego_file in policy_dir.rglob("*.rego"):
                arcname = rego_file.relative_to(policy_dir.parent)
                tar.add(rego_file, arcname=str(arcname))
        return output_path

    def publish_to_s3(self, bundle_path: str | Path, key: str | None = None) -> str:
        bundle_path = Path(bundle_path)
        sha256 = hashlib.sha256(bundle_path.read_bytes()).hexdigest()[:8]
        s3_key = key or f"bundles/{bundle_path.stem}-{sha256}.tar.gz"
        self._s3.upload_file(
            str(bundle_path), self._bucket, s3_key,
            ExtraArgs={"ServerSideEncryption": "AES256", "Metadata": {"sha256": sha256}},
        )
        url = f"s3://{self._bucket}/{s3_key}"
        log.info("Bundle published to %s", url)
        return url

    def update_opa_bundle(self, bundle_path: str | Path) -> bool:
        """Trigger OPA to reload its bundle by updating via the management API."""
        try:
            # OPA Data API — uploading a bundle manually
            with open(bundle_path, "rb") as f:
                resp = self._http.put(
                    f"{self._opa_url}/v1/policies/bundle",
                    content=f.read(),
                    headers={"Content-Type": "application/gzip"},
                )
            resp.raise_for_status()
            log.info("OPA bundle reloaded at %s", self._opa_url)
            return True
        except Exception as e:
            log.error("OPA bundle update failed: %s", e)
            return False

    def sign_bundle(self, bundle_path: str | Path, private_key_path: str | Path) -> Path:
        bundle_path = Path(bundle_path)
        signed_path = bundle_path.with_suffix(".signed.tar.gz")
        cmd = ["opa", "sign", str(bundle_path), "--signing-key", str(private_key_path),
               "--output-file-path", str(signed_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"opa sign failed:\n{result.stderr}")
        log.info("Bundle signed: %s", signed_path)
        return signed_path

    def close(self) -> None:
        self._http.close()

# _r 20260601153104-98503502
