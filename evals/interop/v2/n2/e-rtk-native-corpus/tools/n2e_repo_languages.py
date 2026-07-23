"""Repo -> (language, RTK command family) map for the SWE-bench Multilingual
candidate pool, plus the RTK-native test/build/lint commands per family.

The map is curated from the well-known upstream projects in the pinned dataset
revision; it is data, not inference at runtime. Only the families in the §6
target matrix (rust_cargo / go / js_ts / jvm) are eligible test-runner sources
from SWE-bench Multilingual; Python is absent from Multilingual by design and is
sourced from the BugsInPy reserve.
"""

# repo -> (language, rtk_family). Families outside the §6 matrix are marked with
# their language but rtk_family=None so the inventory records them as ineligible
# for the test-runner strata with a deterministic reason.
REPO_LANGUAGE = {
    # Rust -> rust_cargo
    "astral-sh/ruff": ("rust", "rust_cargo"),
    "burntsushi/ripgrep": ("rust", "rust_cargo"),
    "tokio-rs/axum": ("rust", "rust_cargo"),
    "tokio-rs/tokio": ("rust", "rust_cargo"),
    "nushell/nushell": ("rust", "rust_cargo"),
    "sharkdp/bat": ("rust", "rust_cargo"),
    "uutils/coreutils": ("rust", "rust_cargo"),
    # Go -> go
    "caddyserver/caddy": ("go", "go"),
    "gin-gonic/gin": ("go", "go"),
    "gohugoio/hugo": ("go", "go"),
    "hashicorp/terraform": ("go", "go"),
    "prometheus/prometheus": ("go", "go"),
    # JS/TS -> js_ts
    "axios/axios": ("javascript", "js_ts"),
    "babel/babel": ("javascript", "js_ts"),
    "facebook/docusaurus": ("typescript", "js_ts"),
    "immutable-js/immutable-js": ("typescript", "js_ts"),
    "mrdoob/three.js": ("javascript", "js_ts"),
    "preactjs/preact": ("typescript", "js_ts"),
    "vuejs/core": ("typescript", "js_ts"),
    # Java/JVM -> jvm
    "apache/druid": ("java", "jvm"),
    "apache/lucene": ("java", "jvm"),
    "google/gson": ("java", "jvm"),
    "javaparser/javaparser": ("java", "jvm"),
    "projectlombok/lombok": ("java", "jvm"),
    "reactivex/rxjava": ("java", "jvm"),
    # Present in the dataset but OUTSIDE the §6 target matrix (recorded ineligible)
    "fmtlib/fmt": ("cpp", None),
    "nlohmann/json": ("cpp", None),
    "micropython/micropython": ("c", None),
    "redis/redis": ("c", None),
    "valkey-io/valkey": ("c", None),
    "jqlang/jq": ("c", None),
    "faker-ruby/faker": ("ruby", None),
    "jekyll/jekyll": ("ruby", None),
    "rubocop/rubocop": ("ruby", None),
    "fastlane/fastlane": ("ruby", None),
    "jordansissel/fpm": ("ruby", None),
    "laravel/framework": ("php", None),
    "php-cs-fixer/php-cs-fixer": ("php", None),
    "phpoffice/phpspreadsheet": ("php", None),
    "briannesbitt/carbon": ("php", None),
}

# RTK-native command per family (test / build / lint subfamilies), argv form.
FAMILY_RTK_COMMANDS = {
    "rust_cargo": {
        "test": ["rtk", "cargo", "test"],
        "build": ["rtk", "cargo", "build"],
        "check": ["rtk", "cargo", "check"],
        "clippy": ["rtk", "cargo", "clippy"],
    },
    "go": {
        "test": ["rtk", "go", "test", "./..."],
        "build": ["rtk", "go", "build", "./..."],
        "vet": ["rtk", "go", "vet", "./..."],
    },
    "js_ts": {
        "jest": ["rtk", "jest"],
        "vitest": ["rtk", "vitest"],
        "tsc": ["rtk", "tsc"],
        "lint": ["rtk", "lint", "."],
    },
    "jvm": {
        "mvn_test": ["rtk", "mvn", "test"],
        "gradlew_test": ["rtk", "gradlew", "test"],
    },
    "python": {
        "pytest": ["rtk", "pytest"],
        "ruff": ["rtk", "ruff", "check", "."],
    },
}


def language_of(repo: str) -> str | None:
    e = REPO_LANGUAGE.get(repo)
    return e[0] if e else None


def family_of(repo: str) -> str | None:
    e = REPO_LANGUAGE.get(repo)
    return e[1] if e else None
