// SPDX-FileCopyrightText: 2021 HH Partners
//
// SPDX-License-Identifier: MIT

//! Regression tests for the tag-value parser's section handling.
//!
//! Each case below was a silent data loss or corruption before the parser tracked which
//! section it was in.

use spdx_rs::{models::PrimaryPackagePurpose, parsers::spdx_from_tag_value};

const HEADER: &str = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: Probe
DocumentNamespace: https://example.com/probe
Creator: Person: Test (test@example.com)
Created: 2026-09-17T00:00:00Z
";

fn parse(body: &str) -> spdx_rs::models::SPDX {
    spdx_from_tag_value(&format!("{HEADER}\n{body}")).unwrap()
}

/// The pending external reference used to be held beside the package and only committed
/// when the *next* `ExternalRef` or `PackageName` arrived, so the last one in the document
/// was dropped along with its comment.
#[test]
fn last_external_ref_of_last_package_is_kept() {
    let spdx = parse(
        "\
PackageName: PkgA
SPDXID: SPDXRef-Package-PkgA
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
ExternalRef: SECURITY cpe23Type cpe:2.3:a:vendor:pkga:1.0.0:*:*:*:*:*:*:*

PackageName: PkgB
SPDXID: SPDXRef-Package-PkgB
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
ExternalRef: SECURITY cpe23Type cpe:2.3:a:vendor:pkgb:2.0.0:*:*:*:*:*:*:*
ExternalRefComment: comment on the very last ref
",
    );

    let refs = |name: &str| {
        spdx.package_information
            .iter()
            .find(|p| p.package_name == name)
            .unwrap_or_else(|| panic!("package {} missing", name))
            .external_reference
            .clone()
    };

    assert_eq!(refs("PkgA").len(), 1, "non-final package lost its ref");
    assert_eq!(refs("PkgB").len(), 1, "FINAL package lost its ref");
    assert!(refs("PkgB")[0].reference_locator.contains("pkgb"));
    assert_eq!(
        refs("PkgB")[0].reference_comment.as_deref(),
        Some("comment on the very last ref"),
        "ExternalRefComment on the final ref was lost"
    );
}

/// These six tags were lexed into atoms and then fell through a `_ => {}` arm.
#[test]
fn tags_that_used_to_fall_through_are_assigned() {
    let spdx = parse(
        "\
PackageName: LibPkg
SPDXID: SPDXRef-Package-LibPkg
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageComment: <text>a package comment</text>
PrimaryPackagePurpose: LIBRARY
BuiltDate: 2024-01-01T00:00:00Z
ReleaseDate: 2024-02-01T00:00:00Z
ValidUntilDate: 2024-03-01T00:00:00Z

FileName: ./f.c
SPDXID: SPDXRef-File-F
FileAttributionText: <text>attribution here</text>
",
    );

    let package = &spdx.package_information[0];
    assert_eq!(
        package.package_comment.as_deref(),
        Some("a package comment")
    );
    assert_eq!(
        package.primary_package_purpose,
        Some(PrimaryPackagePurpose::Library)
    );
    assert_eq!(package.built_date.as_deref(), Some("2024-01-01T00:00:00Z"));
    assert_eq!(
        package.release_date.as_deref(),
        Some("2024-02-01T00:00:00Z")
    );
    assert_eq!(
        package.valid_until_date.as_deref(),
        Some("2024-03-01T00:00:00Z")
    );

    assert_eq!(
        spdx.file_information[0].file_attribution_text.as_deref(),
        Some(["attribution here".to_string()].as_slice())
    );
}

/// Tag-value spells it `OPERATING-SYSTEM`; the JSON serialisation of the same enum uses
/// `OPERATING_SYSTEM`. Both must parse.
#[test]
fn operating_system_purpose_accepts_both_spellings() {
    for spelling in ["OPERATING-SYSTEM", "OPERATING_SYSTEM"] {
        let spdx = parse(&format!(
            "\
PackageName: OsPkg
SPDXID: SPDXRef-Package-OsPkg
PackageDownloadLocation: NOASSERTION
PrimaryPackagePurpose: {spelling}
"
        ));
        assert_eq!(
            spdx.package_information[0].primary_package_purpose,
            Some(PrimaryPackagePurpose::OperatingSystem),
            "failed for {spelling}"
        );
    }
}

/// `SPDXID` is the only tag shared between the document, package and file sections. It used
/// to be routed by checking whether the package's identifier was still the `Default`
/// sentinel, so a package without one stole the following file's identifier and emitted a
/// self-referential `CONTAINS` edge.
#[test]
fn spdxid_is_routed_by_section_not_by_sentinel() {
    let spdx = parse(
        "\
PackageName: NoIdPkg
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: true

FileName: ./f.c
SPDXID: SPDXRef-File-F
",
    );

    assert_eq!(
        spdx.file_information[0].file_spdx_identifier,
        "SPDXRef-File-F"
    );
    assert_ne!(
        spdx.package_information[0].package_spdx_identifier, "SPDXRef-File-F",
        "package stole the file's identifier"
    );
    assert!(
        !spdx
            .relationships
            .iter()
            .any(|r| r.spdx_element_id == r.related_spdx_element),
        "emitted a self-referential relationship"
    );
}

/// A package that does carry an identifier still gets its implicit `CONTAINS` edges, and
/// only for the files that follow it.
#[test]
fn files_are_contained_by_the_preceding_package() {
    let spdx = parse(
        "\
FileName: ./before.c
SPDXID: SPDXRef-Before

PackageName: Pkg
SPDXID: SPDXRef-Package
PackageDownloadLocation: NOASSERTION

FileName: ./after.c
SPDXID: SPDXRef-After
",
    );

    let contains: Vec<_> = spdx
        .relationships
        .iter()
        .map(|r| (r.spdx_element_id.as_str(), r.related_spdx_element.as_str()))
        .collect();
    assert_eq!(contains, [("SPDXRef-Package", "SPDXRef-After")]);
}

/// The relationship set used to be drained out of a `HashSet`, so the order of
/// `SPDX::relationships` varied between runs of the same input.
#[test]
fn relationship_order_is_deterministic() {
    let document = std::fs::read_to_string("tests/data/SPDXTagExample-v2.3.spdx").unwrap();
    let first = spdx_from_tag_value(&document).unwrap();
    let second = spdx_from_tag_value(&document).unwrap();
    assert_eq!(first.relationships, second.relationships);
}

/// Unknown tags and unknown enum literals used to hit `unimplemented!()` / `todo!()` and
/// abort the process. A library should hand back an error instead.
#[test]
fn unknown_input_is_an_error_not_a_panic() {
    let unknown_tag = format!("{HEADER}NoSuchTag: whatever\n");
    assert!(spdx_from_tag_value(&unknown_tag).is_err(), "unknown tag");

    let unknown_purpose = format!(
        "{HEADER}\nPackageName: P\nSPDXID: SPDXRef-P\nPrimaryPackagePurpose: NOT-A-PURPOSE\n"
    );
    assert!(
        spdx_from_tag_value(&unknown_purpose).is_err(),
        "unknown PrimaryPackagePurpose"
    );

    let unknown_file_type = format!("{HEADER}\nFileName: ./f.c\nFileType: NOT-A-TYPE\n");
    assert!(
        spdx_from_tag_value(&unknown_file_type).is_err(),
        "unknown FileType"
    );
}
