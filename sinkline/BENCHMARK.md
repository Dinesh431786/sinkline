# Sinkline — Measured Benchmark

_Reproduce: `python benchmark.py`. Corpus: 31 malicious (faithful reconstructions of documented campaigns) + 34 realistic benign hard-negatives. Ran in 196 ms._

## Headline metrics

| Metric | Value |
|---|---|
| Detection recall (correct category) | **31/31 = 100.0%** |
| CI-gate recall (any High+ alert on malware) | 29/31 = 93.5% |
| **False-positive rate** (benign breaking `--fail-on High`) | **0/34 = 0.0%** |
| Precision | 100.0% |
| F1 | 0.967 |
| Confusion | TP=29 FN=2 FP=0 TN=34 |

## Per-sample

| Class | Sample | Expected | Category hit | CI alert |
|---|---|---|---|---|
| MAL | probabilistic_bomb | PROBABILISTIC_BOMB | ✅ | 🚨 |
| MAL | chained_bomb | CHAINED_TRIGGER_BOMB | ✅ | 🚨 |
| MAL | cross_func_bomb | CROSS_FUNCTION_BOMB | ✅ | 🚨 |
| MAL | stego_chr_xor | ENCODED_STRING_PAYLOAD | ✅ | 🚨 |
| MAL | exec_base64 | OBFUSCATED_PAYLOAD | ✅ | 🚨 |
| MAL | xor_blob_exec | OBFUSCATED_PAYLOAD | ✅ | 🚨 |
| MAL | cred_exfil_direct | CREDENTIAL_EXFILTRATION | ✅ | 🚨 |
| MAL | ssh_key_exfil | CREDENTIAL_EXFILTRATION | ✅ | 🚨 |
| MAL | install_hook | INSTALL_HOOK | ✅ | 🚨 |
| MAL | env_keying | ENVIRONMENT_KEYING | ✅ | 🚨 |
| MAL | ai_evasion | AI_SCANNER_EVASION | ✅ | 🚨 |
| MAL | sql_injection | SQL_INJECTION | ✅ | 🚨 |
| MAL | cmd_injection | COMMAND_INJECTION | ✅ | 🚨 |
| MAL | os_system_fmt | COMMAND_INJECTION | ✅ | 🚨 |
| MAL | pickle_loads | INSECURE_DESERIALIZATION | ✅ | 🚨 |
| MAL | yaml_load | INSECURE_DESERIALIZATION | ✅ | 🚨 |
| MAL | eval_input | DANGEROUS_SINK | ✅ | 🚨 |
| MAL | antidebug_sleep | ANTI_ANALYSIS_TIMING | ✅ | — |
| MAL | hardcoded_secret | HARDCODED_SECRET | ✅ | 🚨 |
| MAL | disabled_tls | DISABLED_CERT_VALIDATION | ✅ | 🚨 |
| MAL | weak_hash_pw | WEAK_HASH | ✅ | 🚨 |
| MAL | ssrf | SSRF | ✅ | — |
| MAL | path_traversal | PATH_TRAVERSAL | ✅ | 🚨 |
| MAL | xxe | XXE | ✅ | 🚨 |
| MAL | insecure_random_token | INSECURE_RANDOM | ✅ | 🚨 |
| MAL | aws_secret_leak | EXPOSED_SECRET | ✅ | 🚨 |
| MAL | private_key_leak | EXPOSED_SECRET | ✅ | 🚨 |
| MAL | github_token_leak | EXPOSED_SECRET | ✅ | 🚨 |
| MAL | typosquat_req | TYPOSQUAT_DEPENDENCY | ✅ | 🚨 |
| MAL | slopsquat_req | TYPOSQUAT_DEPENDENCY | ✅ | 🚨 |
| MAL | cross_file_exfil | CREDENTIAL_EXFILTRATION | ✅ | 🚨 |
| BEN | flask_run | - | ✅ | — |
| BEN | subprocess_list | - | ✅ | — |
| BEN | md5_nonsecurity | - | ✅ | — |
| BEN | sha256_ok | - | ✅ | — |
| BEN | random_sampling | - | ✅ | — |
| BEN | random_ab_test | - | ✅ | — |
| BEN | yaml_safe | - | ✅ | — |
| BEN | sql_parameterized | - | ✅ | — |
| BEN | verify_true | - | ✅ | — |
| BEN | requests_const_url | - | ✅ | — |
| BEN | chr_formatting | - | ✅ | — |
| BEN | encode_decode | - | ✅ | — |
| BEN | env_debug_print | - | ✅ | — |
| BEN | env_ci_print | - | ✅ | — |
| BEN | pickle_dump_only | - | ✅ | — |
| BEN | open_config | - | ✅ | — |
| BEN | argparse_cli | - | ✅ | — |
| BEN | dataclass_code | - | ✅ | — |
| BEN | pandas_groupby | - | ✅ | — |
| BEN | plain_function | - | ✅ | — |
| BEN | legit_requirements | - | ✅ | — |
| BEN | legit_pyproject | - | ✅ | — |
| BEN | base64_encode_cfg | - | ✅ | — |
| BEN | comment_security_word | - | ✅ | — |
| BEN | logging_debug | - | ✅ | — |
| BEN | tempfile_mkstemp | - | ✅ | — |
| BEN | secrets_token | - | ✅ | — |
| BEN | ssl_default_ctx | - | ✅ | — |
| BEN | class_methods | - | ✅ | — |
| BEN | env_to_config | - | ✅ | — |
| BEN | random_shuffle | - | ✅ | — |
| BEN | ignore_word_comment | - | ✅ | — |
| BEN | secret_placeholder | - | ✅ | — |
| BEN | secret_from_env | - | ✅ | — |
