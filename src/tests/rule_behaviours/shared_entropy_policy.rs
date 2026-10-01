//! Check shared entropy decisions through the same project scan a user runs.
//!
//! Public source projections must stay quiet and authored opaque mutations must report.
//! These controls preserve complete-value boundaries across the family policy.

use super::*;

/// Check the complete URL guard independently of native extraction, which excludes colon-bearing URLs.
#[test]
pub(crate) fn commit_reference_policy_rejects_extra_components() {
    assert!(
        crate::built_in_rules::is_structured_high_entropy_non_secret(
            "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e"
        )
    );
    let invalid_references = [
        "http://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
        "https://reader:@github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
        "https://github.com:443/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
        "https://github.com.invalid/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
        "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e?mode=debug",
        "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e#details",
        "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e/details",
        "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10",
        "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e0",
        "https://github.com/python/cpython/commit/6E8DCDAAA49D4313BF9FAB9F9923CA5828FBB10E",
        "https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10eq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0",
        "https://github.com/-python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
        "https://github.com/python-/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
        "https://github.com/python/.cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
        "https://github.com/python//commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e",
    ];
    // A malformed component must not gain an exception if a future caller supplies the complete URL.
    for reference in invalid_references {
        assert!(
            !crate::built_in_rules::is_structured_high_entropy_non_secret(reference),
            "{reference}"
        );
    }
}

/// Check complete stored help links so malformed titles cannot hide a warning.
#[test]
pub(crate) fn article_route_policy_rejects_extra_components() {
    assert!(
        crate::built_in_rules::is_structured_high_entropy_non_secret(
            "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy"
        )
    );
    let invalid_routes = [
        "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy\n",
        "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy?mode=debug",
        "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy#details",
        "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy/details",
        "prefix /hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy suffix",
        "/hc/en-au/articles/1234567890123--to-fax-messages-in-Halaxy",
        "/hc/en-au/articles/1234567890123-gUiDe-to-fax-messages-in-Halaxy",
        "/hc/en-au/articles/1234567890123-AlphabeticRepresentationReference-to-fax-messages-in-Halaxy",
        "/hc/en-au/articles/1234567890123-Guide2-to-fax-messages-in-Halaxy",
        "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-IN-Halaxy",
 ];
    // Extra components or malformed title words cannot inherit the readable article's exception.
    for invalid_route in invalid_routes {
        assert!(
            !crate::built_in_rules::is_structured_high_entropy_non_secret(invalid_route),
            "{invalid_route}"
        );
    }
}

/// Check the complete portal guard independently of native extraction; the UUID is synthetic.
#[test]
pub(crate) fn portal_reference_policy_rejects_extra_components() {
    assert!(crate::built_in_rules::is_structured_high_entropy_non_secret("https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true"));
    let invalid_references = [
        "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true\n",
        "http://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
        "https://reader:@entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
        "https://entra.microsoft.com:443/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
        "https://entra.microsoft.com.invalid/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
        "https://entra.microsoft.com/?mode=debug#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
        "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcde/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
        "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89AB-CDEF-0123-456789ABCDEF/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
        "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
        "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/true?Microsoft_AAD_IAM_legacyAADRedirect=true",
        "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=false",
        "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true&mode=debug",
        "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true#details",
        "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=trueq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0",
        "prefix https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true suffix",
        "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z001234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
    ];
    // Every extra or malformed component must prevent the complete-value exception.
    for reference in invalid_references {
        assert!(!crate::built_in_rules::is_structured_high_entropy_non_secret(reference));
    }
}

/// Common JSON-value projections preserve the 15 F01 decisions while opaque mutations remain reportable.
#[test]
pub(crate) fn high_entropy_shared_policy_checks_complete_values() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let cases = [
        ("/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy", false),
        ("/hc/en-au/articles/123456789012-Guide-to-fax-messages-in-Halaxy", false),
        ("/hc/en-au/articles/1234567890123-Deactivate-a-user-from-your-group", false),
        ("https://support.halaxy.com/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy", false),
        ("/support/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy", true),
        ("/hc/en-au/articles/12345678901-Guide-to-fax-messages-in-Halaxy", true),
        ("/hc/en-au/articles/12345678901234-Guide-to-fax-messages-in-Halaxy", true),
        ("/hc/en-au/articles/1234567890123-Guide-by-fax-messages", true),
        ("/hc/en-au/articles/1234567890123-Guide-TO-fax-messages", true),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy", true),
        ("/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxyq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy-q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("/hc/en-au/sections/123456789012-Guide-to-fax-messages-in-Halaxy", true),
        ("abcdefghijklmnopqrstuvwxyz0123456789", false),
        ("bacdefghijklmnopqrstuvwxyz0123456789", true),
        ("abcdefghijklmnopqrstuvwxyz01234567899", true),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0abcdefghijklmnopqrstuvwxyz0123456789", true),
        ("abcdefghijklmnopqrstuvwxyz0123456789q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", false),
        ("BACDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", true),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567899", true),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", true),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("security.access_token_handler.oidc.signature.ES256", false),
        ("security.access_token_handler.oidc.signature.ES384", false),
        ("security.access_token_handler.oidc.signature.ES512", false),
        ("security.access_token_handler.oidc.signature.RS256", false),
        ("security.access_token_handler.oidc.signature.RS384", false),
        ("security.access_token_handler.oidc.signature.RS512", false),
        ("security.access_token_handler.oidc.signature.PS256", false),
        ("security.access_token_handler.oidc.signature.PS384", false),
        ("security.access_token_handler.oidc.signature.PS512", false),
        ("security.access_token_handler.oidc.signature.HS512", true),
        ("security.access_token_handler.oidc.signature.PS513", true),
        ("security.access_token_handler.oidc.signature.ps512", true),
        ("other.security.access_token_handler.oidc.signature.PS512", true),
        ("security.access_token_handler.oidc.signature.PS512q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0security.access_token_handler.oidc.signature.PS512", true),
        ("https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true", false),
        ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", false),
        ("1023456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", true),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z00123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", true),
        ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e", false),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("/hc/en-au/categories/360002157933-Schedule", false),
        ("https://support.halaxy.com/hc/en-au/articles/6033481017999-Customise-your-reminder-templates", false),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", false),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/==", true),
        ("BACDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", true),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", true),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("/hc/en-au/categories/360002157933-Scheduleq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("public/hc/en-au/categories/360002157933-Schedule", true),
        ("/hc/en-au/categories/360002157933-Schedule-Ab", true),
        ("/hc/en-au/categories/360002157933-ScHeDuLe", true),
        ("/hc/en-au/categories/360002157933-Schedule-AlphabeticRepresentationReference", true),
        ("/hc/en-au/categories/360002157933-Schedule-123", true),
        ("/hc/en-au/categories/3600021579337-Schedule", true),
        ("github.com/aws/aws-sdk-go-v2/feature/ec2/imds", false),
        ("../../examples/tutorial_derive/03_02_option_mult.md", false),
        ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", false),
        ("github.com/aws/aws-sdk-go-v2/feature/ec2/imdsq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("../../manuals/tutorial_derive/03_02_option_mult.mdq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("../../../manuals/tutorial_derive/03_02_option_mult.md/DeveloperGuide", true),
        ("github.com/aws/aws-sdk-go-v2/feature/ec23/imds", true),
        ("bcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890a", true),
        ("https://support.halaxy.com/hc/en-au/articles/360044495693-Deactivate-a-user-from-your-group", false),
        ("https://sqs.ap-southeast-2.amazonaws.com/123456789012/media-concat-processing-queue?auto_setup=false", false),
        ("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789", false),
        ("ComposerAutoloaderInit386a05f6676643b8b2eb49288e20d079", true),
        ("Cryptography_HAS_TLSv1_3_HS_FUNCTIONS", false),
        ("chacha20poly1305_bad_tag_second_chunk_full", false),
        ("Cryptography_STACK_OF_X509_OBJECT *X509_STORE_get0_objects(X509_STORE *);", false),
        ("int sk_X509_OBJECT_num(Cryptography_STACK_OF_X509_OBJECT *);", false),
        ("Cryptography_HAS_TLSv1_3_FUNCTIONS", false),
        ("cryptography-manylinux2014_aarch64", false),
        ("aes256gcm_bad_tag_empty_final_chunk", false),
        ("static const long Cryptography_HAS_TLSv1_3_HS_FUNCTIONS = 0;", false),
        ("chacha20poly1305_bad_tag_first_chunk", false),
        ("soljson-v0.8.21+commit.d9974bed.js", false),
        ("./node_modules/core-js/internals/v8-prototype-define-bug.js", false),
        ("SNYK-JS-EXPRESSFILEUPLOAD-473997", false),
        ("1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq.apps.googleusercontent.com", false),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789", true),
        ("public_metadata_q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("public_metadata_alphaq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("public_metadata_q7W9e2R4t6Y8u1I3o5P0_a9S7d5F3g1H8j6K4l2Z0", true),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq.apps.googleusercontent.comq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", false),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", false),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_", false),
        ("abcdefghijklmnopqrstuvwxyz0123456789-_", false),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", false),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", false),
        ("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789", false),
        ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_", false),
        ("Com.Example2.Services.Authentication.TokenProvider", false),
        ("docs/decisions/ADR-020-DeferCorpusScoringParity2.md", false),
        ("deepseek-ai/DeepSeek-R1-Distill-Qwen-32B", false),
        ("Qwen/Qwen2.5-Coder-32B-Instruct-AWQ", false),
        (".goat-flow/tasks/0.1/M38-css-metrics-and-todo-density-calibration.md", false),
        ("/repo/.goat-flow/tasks/1.7.0/M00-side-menu-navigation.md", false),
        (".goat-flow/tasks/0.1/M38-css-metrics-and-todo-density-calibration.mdq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("/repo/.goat-flow/tasks/1.7.0/M00-side-menu-navigation.mdq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("..goat-flow/tasks/0.1/M38-css-metrics-and-todo-density-calibration.md", true),
        ("//repo/.goat-flow/tasks/1.7.0/M00-side-menu-navigation.md", true),
        ("Automattic/i18n-check-webpack-plugin", false),
        ("var/quality/full-corpus-20260710T2328Z/primock57-day2-consultation09-i-cant-move-my-left-arm/live-history.json", false),
        ("var/quality/0.5.0-harness-20260717T011802Z/t02.9-holdout-registration.tsv", false),
        ("/hc/en-au/sections/360005188513-Appointments", false),
        ("/hc/en-au/sections/360005149694-Communication-Report", false),
        ("PH_ObservationInterpretation_HL7_V3", false),
        ("PHVS_ObservationInterpretation_HL7_V3", false),
        ("Automattic/i18n-check-webpack-pluginq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("var/quality/full-corpus-20260710T2328Z/primock57-day2-consultation09-i-cant-move-my-left-arm/live-history.jsonq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("var/quality/0.5.0-harness-20260717T011802Z/t02.9-holdout-registration.tsvq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("/hc/en-au/sections/360005188513-Appointmentsq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("/hc/en-au/sections/360005149694-Communication-Reportq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("PH_ObservationInterpretation_HL7_V3q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("PHVS_ObservationInterpretation_HL7_V3q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", true),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0/hc/en-au/sections/360005188513-Appointments", true),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0PH_ObservationInterpretation_HL7_V3", true),
    ];
    let literals: String = cases
        .iter()
        .map(|(candidate, _)| format!("let _probe = {candidate:?};\n"))
        .collect();
    baseline_with_lib(
        dir.path(),
        &format!("/// Public entropy controls.\npub fn entry() {{\n{literals}}}\n"),
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let observed: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.high-entropy-string")
        .filter_map(|finding| finding.line)
        .collect();
    let expected: Vec<_> = cases
        .iter()
        .enumerate()
        .filter(|(_, (_, should_report))| *should_report)
        .map(|(index, _)| index + 3)
        .collect();
    assert_eq!(observed, expected);
}
