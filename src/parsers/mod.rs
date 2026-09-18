// SPDX-FileCopyrightText: 2021 HH Partners
//
// SPDX-License-Identifier: MIT

//! Parsers for deserializing [`SPDX`] from different data formats.
//!
//! The SPDX spec supports some data formats that are not supported by [Serde], so parsing from JSON
//! (and YAML) is achieved with the data format specific crates:
//!
//! ```rust
//! # use spdx_rs::error::SpdxError;
//! use spdx_rs::models::SPDX;
//! # fn main() -> Result<(), SpdxError> {
//!
//! let spdx_file = std::fs::read_to_string("tests/data/SPDXJSONExample-v2.2.spdx.json")?;
//! let spdx_document: SPDX = serde_json::from_str(&spdx_file).unwrap();
//!
//! assert_eq!(
//!     spdx_document.document_creation_information.document_name,
//!     "SPDX-Tools-v2.0"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! [Serde]: https://serde.rs

use crate::{
    error::SpdxError,
    models::SPDX,
    parsers::{builder::SpdxBuilder, tag_value::atoms},
};

mod builder;
mod tag_value;

/// Parse a tag-value SPDX document to [`SPDX`].
///
/// # Usage
///
/// ```
/// # use spdx_rs::error::SpdxError;
/// use spdx_rs::parsers::spdx_from_tag_value;
/// # fn main() -> Result<(), SpdxError> {
///
/// let spdx_file = std::fs::read_to_string("tests/data/SPDXTagExample-v2.2.spdx")?;
/// let spdx_document = spdx_from_tag_value(&spdx_file)?;
///
/// assert_eq!(
///     spdx_document.document_creation_information.document_name,
///     "SPDX-Tools-v2.0"
/// );
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// - If parsing of the tag-value fails.
/// - If parsing of some of the values fail.
pub fn spdx_from_tag_value(input: &str) -> Result<SPDX, SpdxError> {
    let (_, atoms) = atoms(input).map_err(|err| SpdxError::TagValueParse(err.to_string()))?;

    SpdxBuilder::build(&atoms)
}

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod test_super {
    use std::{collections::HashSet, fs::read_to_string, iter::FromIterator};

    use chrono::{TimeZone, Utc};
    use spdx_expression::SpdxExpression;

    use crate::models::{
        Algorithm, Annotation, AnnotationType, Checksum, ExternalDocumentReference,
        ExternalPackageReference, ExternalPackageReferenceCategory, FileType, Pointer,
        Relationship,
    };

    use super::*;

    #[test]
    fn whole_spdx_is_parsed() {
        let file = read_to_string("tests/data/SPDXTagExample-v2.2.spdx").unwrap();
        let spdx = spdx_from_tag_value(&file).unwrap();
        assert_eq!(spdx.package_information.len(), 4);
        assert_eq!(spdx.file_information.len(), 4);
    }

    #[test]
    fn spdx_creation_info_is_retrieved() {
        let file = read_to_string("tests/data/SPDXTagExample-v2.2.spdx").unwrap();
        let spdx = spdx_from_tag_value(&file).unwrap();
        let document_creation_information = spdx.document_creation_information;
        assert_eq!(document_creation_information.spdx_version, "SPDX-2.2");
        assert_eq!(document_creation_information.data_license, "CC0-1.0");
        assert_eq!(
            document_creation_information.spdx_document_namespace,
            "http://spdx.org/spdxdocs/spdx-example-444504E0-4F89-41D3-9A0C-0305E82C3301"
        );
        assert_eq!(
            document_creation_information.document_name,
            "SPDX-Tools-v2.0"
        );
        assert_eq!(
            document_creation_information.spdx_identifier,
            "SPDXRef-DOCUMENT"
        );
        assert_eq!(
            document_creation_information.document_comment,
            Some(
                "This document was created using SPDX 2.0 using licenses from the web site."
                    .to_string()
            )
        );
        assert_eq!(
            document_creation_information.external_document_references,
            vec![ExternalDocumentReference::new(
                "spdx-tool-1.2".to_string(),
                "http://spdx.org/spdxdocs/spdx-tools-v1.2-3F2504E0-4F89-41D3-9A0C-0305E82C3301"
                    .to_string(),
                Checksum::new(Algorithm::SHA1, "d6a770ba38583ed4bb4525bd96e50461655d2759")
            )]
        );
        assert!(document_creation_information
            .creation_info
            .creators
            .contains(&"Tool: LicenseFind-1.0".to_string()));
        assert!(document_creation_information
            .creation_info
            .creators
            .contains(&"Organization: ExampleCodeInspect ()".to_string()));
        assert!(document_creation_information
            .creation_info
            .creators
            .contains(&"Person: Jane Doe ()".to_string()));
        assert_eq!(
            document_creation_information.creation_info.created,
            Utc.with_ymd_and_hms(2010, 1, 29, 18, 30, 22).unwrap()
        );
        assert_eq!(
            document_creation_information.creation_info.creator_comment,
            Some(
                "This package has been shipped in source and binary form.
The binaries were created with gcc 4.5.1 and expect to link to
compatible system run time libraries."
                    .to_string()
            )
        );
        assert_eq!(
            document_creation_information
                .creation_info
                .license_list_version,
            Some("3.9".to_string())
        );
    }

    #[test]
    fn package_info_is_retrieved() {
        let file = read_to_string("tests/data/SPDXTagExample-v2.2.spdx").unwrap();
        let spdx = spdx_from_tag_value(&file).unwrap();
        let packages = spdx.package_information;
        assert_eq!(packages.len(), 4);

        let glibc = packages.iter().find(|p| p.package_name == "glibc").unwrap();
        assert_eq!(glibc.package_spdx_identifier, "SPDXRef-Package");
        assert_eq!(glibc.package_version, Some("2.11.1".to_string()));
        assert_eq!(
            glibc.package_file_name,
            Some("glibc-2.11.1.tar.gz".to_string())
        );
        assert_eq!(
            glibc.package_supplier,
            Some("Person: Jane Doe (jane.doe@example.com)".to_string())
        );
        assert_eq!(
            glibc.package_originator,
            Some("Organization: ExampleCodeInspect (contact@example.com)".to_string())
        );
        assert_eq!(
            glibc.package_download_location,
            "http://ftp.gnu.org/gnu/glibc/glibc-ports-2.15.tar.gz".to_string()
        );
        assert_eq!(
            glibc.package_verification_code.as_ref().unwrap().value,
            "d6a770ba38583ed4bb4525bd96e50461655d2758".to_string()
        );
        assert_eq!(
            glibc.package_verification_code.as_ref().unwrap().excludes,
            vec!["./package.spdx"]
        );
        assert_eq!(
            glibc.package_checksum,
            vec![
                Checksum::new(Algorithm::MD5, "624c1abb3664f4b35547e7c73864ad24"),
                Checksum::new(Algorithm::SHA1, "85ed0817af83a24ad8da68c2b5094de69833983c"),
                Checksum::new(
                    Algorithm::SHA256,
                    "11b6d3ee554eedf79299905a98f9b9a04e498210b59f15094c916c91d150efcd"
                ),
            ]
        );
        assert_eq!(
            glibc.package_home_page,
            Some("http://ftp.gnu.org/gnu/glibc".to_string())
        );
        assert_eq!(
            glibc.source_information,
            Some("uses glibc-2_11-branch from git://sourceware.org/git/glibc.git.".to_string())
        );
        assert_eq!(
            glibc.concluded_license.as_ref().unwrap().identifiers(),
            HashSet::from_iter(["LGPL-2.0-only".to_string(), "LicenseRef-3".to_string()])
        );
        assert_eq!(
            glibc.all_licenses_information_from_files,
            vec!["GPL-2.0-only", "LicenseRef-2", "LicenseRef-1"]
        );
        assert_eq!(
            glibc.declared_license.as_ref().unwrap().identifiers(),
            HashSet::from_iter(["LGPL-2.0-only".to_string(), "LicenseRef-3".to_string()])
        );
        assert_eq!(glibc.comments_on_license, Some("The license for this project changed with the release of version x.y.  The version of the project included here post-dates the license change.".to_string()));
        assert_eq!(
            glibc.copyright_text.as_ref().unwrap().clone(),
            "Copyright 2008-2010 John Smith"
        );
        assert_eq!(
            glibc.package_summary_description,
            Some("GNU C library.".to_string())
        );
        assert_eq!(glibc.package_detailed_description, Some("The GNU C Library defines functions that are specified by the ISO C standard, as well as additional features specific to POSIX and other derivatives of the Unix operating system, and extensions specific to GNU systems.".to_string()));
        assert_eq!(
            glibc.package_attribution_text,
            vec!["The GNU C Library is free software.  See the file COPYING.LIB for copying conditions, and LICENSES for notices about a few contributions that require these additional notices to be distributed.  License copyright years may be listed using range notation, e.g., 1996-2015, indicating that every year in the range, inclusive, is a copyrightable year that would otherwise be listed individually.".to_string()]
        );
        assert_eq!(
            glibc.external_reference,
            vec![
                ExternalPackageReference::new(
                    ExternalPackageReferenceCategory::Security,
                    "cpe23Type".to_string(),
                    "cpe:2.3:a:pivotal_software:spring_framework:4.1.0:*:*:*:*:*:*:*".to_string(),
                    None
                ),
                ExternalPackageReference::new(
                    ExternalPackageReferenceCategory::Other,
                    "LocationRef-acmeforge".to_string(),
                    "acmecorp/acmenator/4.1.3-alpha".to_string(),
                    Some("This is the external ref for Acme".to_string())
                ),
            ]
        );
        let jena = packages.iter().find(|p| p.package_name == "Jena").unwrap();
        assert_eq!(jena.package_spdx_identifier, "SPDXRef-fromDoap-0");
        assert_eq!(
            jena.external_reference,
            vec![ExternalPackageReference::new(
                ExternalPackageReferenceCategory::PackageManager,
                "purl".to_string(),
                "pkg:maven/org.apache.jena/apache-jena@3.12.0".to_string(),
                None
            ),]
        );
    }

    #[test]
    fn file_info_is_retrieved() {
        let file = read_to_string("tests/data/SPDXTagExample-v2.2.spdx").unwrap();
        let spdx = spdx_from_tag_value(&file).unwrap();
        let files = spdx.file_information;
        assert_eq!(files.len(), 4);

        let fooc = files
            .iter()
            .find(|p| p.file_name == "./package/foo.c")
            .unwrap();
        assert_eq!(fooc.file_spdx_identifier, "SPDXRef-File");
        assert_eq!(fooc.file_comment, Some("The concluded license was taken from the package level that the file was included in.
This information was found in the COPYING.txt file in the xyz directory.".to_string()));
        assert_eq!(fooc.file_type, vec![FileType::Source]);
        assert_eq!(
            fooc.file_checksum,
            vec![
                Checksum::new(Algorithm::SHA1, "d6a770ba38583ed4bb4525bd96e50461655d2758"),
                Checksum::new(Algorithm::MD5, "624c1abb3664f4b35547e7c73864ad24")
            ]
        );
        assert_eq!(
            fooc.concluded_license.as_ref().unwrap().identifiers(),
            HashSet::from_iter(["LGPL-2.0-only".to_string(), "LicenseRef-2".to_string(),])
        );
        assert_eq!(
            fooc.license_information_in_file,
            vec![
                SpdxExpression::parse("GPL-2.0-only").unwrap(),
                SpdxExpression::parse("LicenseRef-2").unwrap()
            ]
        );
        assert_eq!(fooc.comments_on_license, Some("The concluded license was taken from the package level that the file was included in.".to_string()));
        assert_eq!(
            fooc.copyright_text.as_ref().unwrap().clone(),
            "Copyright 2008-2010 John Smith".to_string()
        );
        assert_eq!(
            fooc.file_notice,
            Some("Copyright (c) 2001 Aaron Lehmann aaroni@vitelus.com

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the �Software�), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: 
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED �AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.".to_string())
        );
        assert_eq!(
            fooc.file_contributor,
            vec![
                "The Regents of the University of California".to_string(),
                "Modified by Paul Mundt lethal@linux-sh.org".to_string(),
                "IBM Corporation".to_string(),
            ]
        );
        let doap = files
            .iter()
            .find(|p| p.file_name == "./src/org/spdx/parser/DOAPProject.java")
            .unwrap();

        assert_eq!(doap.file_spdx_identifier, "SPDXRef-DoapSource");
    }

    #[test]
    fn snippet_info_is_retrieved() {
        let file = read_to_string("tests/data/SPDXTagExample-v2.2.spdx").unwrap();
        let spdx = spdx_from_tag_value(&file).unwrap();
        let snippets = spdx.snippet_information;
        assert_eq!(snippets.len(), 1);

        let snippet = snippets[0].clone();

        assert_eq!(snippet.snippet_spdx_identifier, "SPDXRef-Snippet");
        assert_eq!(
            snippet.snippet_from_file_spdx_identifier,
            "SPDXRef-DoapSource"
        );
        assert_eq!(snippet.ranges.len(), 2);
        assert!(snippet
            .ranges
            .iter()
            .any(|snip| snip.start_pointer == Pointer::new_byte(None, 310)));
        assert!(snippet
            .ranges
            .iter()
            .any(|snip| snip.end_pointer == Pointer::new_byte(None, 420)));
        assert!(snippet
            .ranges
            .iter()
            .any(|snip| snip.start_pointer == Pointer::new_line(None, 5)));
        assert!(snippet
            .ranges
            .iter()
            .any(|snip| snip.end_pointer == Pointer::new_line(None, 23)));
        assert_eq!(
            snippet.snippet_concluded_license.unwrap(),
            SpdxExpression::parse("GPL-2.0-only").unwrap()
        );
        assert_eq!(snippet.license_information_in_snippet, vec!["GPL-2.0-only"]);
        assert_eq!(snippet.snippet_comments_on_license, Some("The concluded license was taken from package xyz, from which the snippet was copied into the current file. The concluded license information was found in the COPYING.txt file in package xyz.".to_string()));
        assert_eq!(
            snippet.snippet_copyright_text.as_ref().unwrap().clone(),
            "Copyright 2008-2010 John Smith"
        );
        assert_eq!(snippet.snippet_comment, Some("This snippet was identified as significant and highlighted in this Apache-2.0 file, when a commercial scanner identified it as being derived from file foo.c in package xyz which is licensed under GPL-2.0.".to_string()));
        assert_eq!(snippet.snippet_name, Some("from linux kernel".to_string()));
    }

    #[test]
    fn relationships_are_retrieved() {
        let file = read_to_string("tests/data/SPDXTagExample-v2.2.spdx").unwrap();
        let spdx = spdx_from_tag_value(&file).unwrap();
        let relationships = spdx.relationships;
        assert_eq!(relationships.len(), 11);

        assert!(relationships.contains(&Relationship::new(
            "SPDXRef-DOCUMENT",
            "SPDXRef-Package",
            crate::models::RelationshipType::Contains,
            None
        )));
        assert!(relationships.contains(&Relationship::new(
            "SPDXRef-CommonsLangSrc",
            "NOASSERTION",
            crate::models::RelationshipType::GeneratedFrom,
            None
        )));

        // Implied relationship by the file following the package in tag-value.
        assert!(relationships.contains(&Relationship::new(
            "SPDXRef-Package",
            "SPDXRef-DoapSource",
            crate::models::RelationshipType::Contains,
            None
        )));
    }

    #[test]
    fn annotations_are_retrieved() {
        let file = read_to_string("tests/data/SPDXTagExample-v2.2.spdx").unwrap();
        let spdx = spdx_from_tag_value(&file).unwrap();
        let annotations = spdx.annotations;
        assert_eq!(annotations.len(), 5);

        assert_eq!(
            annotations[2],
            Annotation::new(
                "Person: Suzanne Reviewer".to_string(),
                Utc.with_ymd_and_hms(2011, 3, 13, 0, 0, 0).unwrap(),
                AnnotationType::Review,
                Some("SPDXRef-DOCUMENT".to_string()),
                "Another example reviewer.".to_string()
            )
        );
    }

    #[test]
    fn license_info_is_retrieved() {
        let file = read_to_string("tests/data/SPDXTagExample-v2.2.spdx").unwrap();
        let spdx = spdx_from_tag_value(&file).unwrap();
        let license_info = spdx.other_licensing_information_detected;
        assert_eq!(license_info.len(), 5);
        assert_eq!(license_info[1].license_identifier, "LicenseRef-2");
        assert_eq!(
            license_info[3].license_name,
            "Beer-Ware License (Version 42)"
        );
        assert_eq!(
            license_info[3].license_cross_reference,
            vec!["http://people.freebsd.org/~phk/"]
        );
        assert_eq!(
            license_info[3].license_comment,
            Some("The beerware license has a couple of other standard variants.".to_string())
        );
        assert!(license_info[3]
            .extracted_text
            .starts_with(r#""THE BEER-WARE"#));
        assert!(license_info[3]
            .extracted_text
            .ends_with("Poul-Henning Kamp"));
    }

    #[test]
    fn tag_value_is_parsed() {
        let file = read_to_string("tests/data/SPDXTagExample-v2.2.spdx").unwrap();
        let spdx = spdx_from_tag_value(&file).unwrap();

        assert_eq!(spdx.package_information.len(), 4);
        assert_eq!(spdx.file_information.len(), 4);
        assert_eq!(spdx.snippet_information.len(), 1);
        assert_eq!(spdx.relationships.len(), 11);
        assert_eq!(spdx.annotations.len(), 5);
        assert_eq!(spdx.other_licensing_information_detected.len(), 5);
    }
}
