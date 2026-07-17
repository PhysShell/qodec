#!/usr/bin/env python3
"""Builds the self-hash-locked artifacts manifest for the real canonical CI
run that produced the accepted N2-D2/N2-D3 evidence (run 29575975971, on
the disposable trigger branch n2d/ci-trigger-full-run, head 46a7986).

Every artifact's id/name/digest below was read directly from GitHub's own
Actions API response for this run (mcp__github__actions_list ->
list_workflow_run_artifacts) during the session that produced the
evidence; the digest is GitHub's own reported SHA-256 of the artifact ZIP,
never recomputed locally (this repository does not retain the raw ZIP
bytes). This is an evidence-only closure commit -- it does not modify
QODEC/RTK runtime, the input bundle, the benchmark workflow, the
applicability map, any measurement row, or any canonical token count.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

IDENTITY_LOCK_DIR = Path(__file__).resolve().parents[1]
OUT_PATH = IDENTITY_LOCK_DIR / "n2d-run-29575975971-artifacts-manifest-v1.json"

RUN_ID = 29575975971
HEAD_BRANCH = "n2d/ci-trigger-full-run"
HEAD_SHA = "46a7986967c1837797f5edc32e79122d839c3de3"

# (artifact_id, name, digest) -- sorted by artifact_id, exactly as returned
# by the GitHub Actions API for run 29575975971.
ARTIFACTS = [
    (8405157824, "n2d-rtk-determinism-probes-canonical", "sha256:cc98b9a4d4fbd192ed271f6fe1e7ca6cdc0dca6ad5e3852204875e643b508689"),
    (8405187931, "n2d2-leg-b-report", "sha256:712e08f285b302016dfb584bd977a0c42ee2f548447cfd85f38ab55a7e34bce0"),
    (8405192745, "n2d2-leg-a-report", "sha256:dbcd1ecbcb12c3c7bd46ce82c3bce584bc82bf7bd0c3ba2b9eddfa8d4dc7bf73"),
    (8405196421, "n2d2-determinism-canary-report-canonical", "sha256:4eec93a0b9b548943a5de993cedeec1a672ebc1e7ae136cad5b7420d478df867"),
    (8405336155, "n2d3-measurement-repo-pyflakes-b", "sha256:02c37305551502ba1d66d647a357ecac88c3f0a0aa1f978e2d7d88b41c226e00"),
    (8405350901, "n2d3-measurement-ci-log-nlog-a", "sha256:dac5893834377641c868b17074915b4e3af804a17c6de6a7f2f3d074099d1b08"),
    (8405359006, "n2d3-measurement-repo-requests-b", "sha256:d82319ab60864ede85d266937fac939a4a279a873ccab65de18783e570be60d1"),
    (8405368930, "n2d3-measurement-repo-pyflakes-a", "sha256:ad6a4e91e392d33c5ad98e64a77932227fe7f6c37cb0e048f7c4621cf63f0f8f"),
    (8405375611, "n2d3-measurement-repo-kubeops-generator-a", "sha256:94c2077b60c01c899ee640f1ba98c1ad3b0a19b98a36103352e9537f1a46039a"),
    (8405377451, "n2d3-measurement-research-corpus-loghub2-b", "sha256:2a547fd2f5566d9f6ede6086c3447c8c391117911c84d15ecfd28c5fa3eb4995"),
    (8405378324, "n2d3-measurement-repo-helm-values-a", "sha256:9ade5a36f627d8218942672f2fe3c0d3a89ce0a4f541dfedf389204dd055922a"),
    (8405378970, "n2d3-measurement-n2a-miner-canary-b", "sha256:c7e28c733eadb123eec56d4e6c8b1262627fc5a3dee2c20f566b7baacef8693d"),
    (8405380433, "n2d3-measurement-repo-docker-java-parser-b", "sha256:062b93a5bd369c6013ded7383a5818588c3079d3ae0808506b7075524ac9b819"),
    (8405380598, "n2d3-measurement-repo-helm-values-b", "sha256:1e43adbe546eb6f00a085b4434c7d25f766bea5c1249a74812d9678b91621d17"),
    (8405380866, "n2d3-measurement-ci-log-jansson-b", "sha256:6434cbf20f517fa596bb3543f2cabc5732a0657e6ffb19b3022a18ce97fa130b"),
    (8405381222, "n2d3-measurement-ci-log-nlog-b", "sha256:252fb8772ba07583ea16c2fd0c134386399f79d43daf68fbf35e96bcae9275f9"),
    (8405382188, "n2d3-measurement-bot-syzbot-do-mkdirat-b", "sha256:2e8960a54ff9e68019b37ecf5da20975ad27fcc3684551d773c3217366e7349c"),
    (8405384601, "n2d3-measurement-bot-syzbot-do-mkdirat-a", "sha256:5ef164b216e862ecc5c7641ef1d3ccc32037fbf31e879af4d2dd490c9fdd8000"),
    (8405393888, "n2d3-measurement-ci-log-spdlog-b", "sha256:7f26214f6ccf6a531f5afdb6525df6d52b030d80363d8c94c5dc9bca3511b239"),
    (8405411008, "n2d3-measurement-repo-rustlings-a", "sha256:1bdc61e39b819a4e36ec015aaefccaffdb02c6be3b09109142ff7b4f2459684c"),
    (8405412679, "n2d3-measurement-repo-dockerfile-parser-rs-a", "sha256:0e1731719825ba013b14d9e3e14a75656b701cea3f12b4df5fc2fe0ea96c8455"),
    (8405414153, "n2d3-measurement-bot-dependabot-black-5206-a", "sha256:fc48da4dcabaa698b1f30df46951070e632b31e670dbee7c6b7988beb5b8a318"),
    (8405417480, "n2d3-measurement-ci-log-spdlog-a", "sha256:5237fc905dd1ad4decf67c572355c4e3dfefa009bdbf916e2e2e854461a133ae"),
    (8405535929, "n2d3-measurement-repo-docker-java-parser-a", "sha256:e74f6adc293c3ab060214bfa911f76d552aa76727b184d1282a9be9633f42dc2"),
    (8405540087, "n2d3-measurement-repo-rustlings-b", "sha256:0756b05c8c2bd44e23f58114d771bedfddd3fc11b9f8b7111a261f3151049368"),
    (8405556773, "n2d3-measurement-repo-kubeops-generator-b", "sha256:057ec1637375cba68d3808414cc25e4ac1bdc0379f7ea06a27bd66913d382166"),
    (8405558454, "n2d3-measurement-repo-requests-a", "sha256:7bc3caf3b7c2cf48cfe86dcc77bcac59ab84d50efbd77c96d5246f010495bca9"),
    (8405560210, "n2d3-measurement-dataset-loghub-v8-a", "sha256:25f7322580855047715e3cea64d2433307e76c25d5a52a75f900a75e935a41ff"),
    (8405560850, "n2d3-measurement-repo-dockerfile-parser-rs-b", "sha256:4b014c95c1605cd6196d37643b2df05a6953774629fbb729969b03bccfcc9fff"),
    (8405563390, "n2d3-measurement-dataset-loghub-v8-b", "sha256:318cf1c29ef6e63aa2ac9dace76846282fda4bf2d79d853b263d911b10833d14"),
    (8405570186, "n2d3-measurement-research-corpus-loghub2-a", "sha256:2f5c284af0e2b86b3d56555dc14730c6f957d1210d03a6fcf00e1b143fab3021"),
    (8405570211, "n2d3-measurement-repo-moshi-a", "sha256:8ed1434d418f636fd2e8ba4bfa959fb21ba3b7f15766894a773db49dbdeb4fb6"),
    (8405573041, "n2d3-measurement-repo-hyperfine-b", "sha256:ec12c3ff85a92c2011a8f0e42b397d3440f8fb1d49baa8190cf4cff45068f8ba"),
    (8405573227, "n2d3-measurement-repo-hyperfine-a", "sha256:1f88aeef1d2f1c217735813398db3e025b0f09042bc98c5e382926c162493b50"),
    (8405573500, "n2d3-measurement-repo-moshi-b", "sha256:bb3c64b715cec79c97919b27eca45358b838a502b75f3f2d1c1777f81b0fbd6e"),
    (8405575066, "n2d3-measurement-ci-log-jansson-a", "sha256:9d7e410595fb1c4d653b434842aff8cf3644271c9a87b172931f9c331b175115"),
    (8405583488, "n2d3-measurement-n2a-miner-canary-a", "sha256:bfbf8ad68f7c402dca955c832162c34f5aac200fd1513b8ad61c09515317e234"),
    (8405603198, "n2d3-measurement-bot-dependabot-black-5206-b", "sha256:24fd282293c051947200450da3a8f11fdbb8f858d6f856c293ebf2b4bcd8f2ff"),
    (8406584829, "n2d3-measurement-dataset-rtn-traffic-ids-a", "sha256:f7c6b795d5c328938ba2aaf669826f0b91f7bea37315b25bde84b6a9b7da1992"),
    (8406708687, "n2d3-measurement-dataset-rtn-traffic-ids-b", "sha256:220981f45792157d9b122debef460e6fc8611ab20b94191fa79baa57677e8cbb"),
    (8406712163, "n2d3-primary-token-benchmark-canonical", "sha256:08625ce43cc9f5f2c5065c148c99daf15c78c64d19c85716ac2fbcfe8b9170e4"),
]


def compute_record_sha256(body: dict) -> str:
    body_for_hash = dict(body)
    body_for_hash["record_sha256"] = None
    canonical = json.dumps(body_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def build_record() -> dict:
    ids = [a[0] for a in ARTIFACTS]
    if len(ids) != len(set(ids)):
        raise RuntimeError("duplicate artifact id in ARTIFACTS")
    if len(ARTIFACTS) != 41:
        raise RuntimeError(f"expected exactly 41 artifacts, got {len(ARTIFACTS)}")

    artifacts = [
        {
            "id": aid,
            "name": name,
            "digest": digest,
            "run_id": RUN_ID,
            "head_branch": HEAD_BRANCH,
            "head_sha": HEAD_SHA,
        }
        for aid, name, digest in sorted(ARTIFACTS, key=lambda a: a[0])
    ]
    body = {
        "record_type": "n2d-run-artifacts-manifest-v1",
        "record_version": 1,
        "schema_version": 1,
        "run_id": RUN_ID,
        "head_branch": HEAD_BRANCH,
        "head_sha": HEAD_SHA,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }
    body["record_sha256"] = compute_record_sha256(body)
    return body


def main() -> None:
    record = build_record()
    OUT_PATH.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT_PATH} (record_sha256={record['record_sha256']})")


if __name__ == "__main__":
    main()
