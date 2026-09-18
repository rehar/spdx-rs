// SPDX-FileCopyrightText: 2021 HH Partners
//
// SPDX-License-Identifier: MIT

//! Assembly of an [`SPDX`] document from a stream of tag-value [`Atom`]s.

use std::{collections::HashSet, mem};

use chrono::{DateTime, Utc};
use log::warn;
use spdx_expression::SpdxExpression;

use crate::{
    error::SpdxError,
    models::{
        Annotation, AnnotationType, DocumentCreationInformation, FileInformation,
        OtherLicensingInformationDetected, PackageInformation, Pointer, Range, Relationship,
        RelationshipType, Snippet, SPDX,
    },
    parsers::tag_value::Atom,
};

/// The entity the builder is currently inside of.
///
/// Tag-value documents have no explicit section delimiters: a section starts at its first
/// tag (`PackageName`, `FileName`, `SnippetSPDXID` or `LicenseID`) and runs until the next
/// one begins. Keeping the in-progress entity *inside* the cursor means it is impossible to
/// be in the file section with no file to write to, or to have two entities open at once.
///
/// The variants are boxed because the entities differ wildly in size.
#[derive(Debug)]
enum Section {
    /// The document creation information, and the resting state between sections.
    Document,
    Package(Box<PackageInformation>),
    File(Box<FileInformation>),
    Snippet(Box<Snippet>),
    OtherLicense(Box<OtherLicensingInformationDetected>),
}

/// The five tags of an annotation block, which may arrive in any order.
///
/// Unlike the other entities an annotation has no opening tag, so it is committed as soon
/// as all five parts are present rather than when the next section starts.
#[derive(Debug, Default)]
struct AnnotationInProgress {
    annotator: Option<String>,
    date: Option<DateTime<Utc>>,
    comment: Option<String>,
    annotation_type: Option<AnnotationType>,
    spdxref: Option<String>,
}

/// Assembles an [`SPDX`] from the atoms of a tag-value document.
#[derive(Debug)]
pub(super) struct SpdxBuilder {
    document_creation_information: DocumentCreationInformation,
    packages: Vec<PackageInformation>,
    files: Vec<FileInformation>,
    snippets: Vec<Snippet>,
    other_licensing: Vec<OtherLicensingInformationDetected>,
    annotations: Vec<Annotation>,

    /// Relationships are kept in document order so that parsing the same input twice
    /// produces byte-identical output; `seen` preserves the de-duplication that the
    /// previous `HashSet` provided.
    relationships: Vec<Relationship>,
    seen_relationships: HashSet<Relationship>,

    /// The one cursor. See [`Section`].
    section: Section,

    /// Identifier of the package whose section most recently closed. This outlives
    /// [`Section::Package`] because the implicit `CONTAINS` edges are emitted while the
    /// *file* section is open, and it is the only state that legitimately spans sections.
    current_package_id: Option<String>,

    /// Relationships and annotations name their own subjects, so they are independent of
    /// the section cursor and may appear anywhere in the document.
    relationship_in_progress: Option<Relationship>,
    annotation_in_progress: AnnotationInProgress,
}

impl SpdxBuilder {
    fn new() -> Self {
        Self {
            document_creation_information: DocumentCreationInformation::default(),
            packages: Vec::new(),
            files: Vec::new(),
            snippets: Vec::new(),
            other_licensing: Vec::new(),
            annotations: Vec::new(),
            relationships: Vec::new(),
            seen_relationships: HashSet::new(),
            section: Section::Document,
            current_package_id: None,
            relationship_in_progress: None,
            annotation_in_progress: AnnotationInProgress::default(),
        }
    }

    /// Build a document from a complete atom stream.
    pub(super) fn build(atoms: &[Atom]) -> Result<SPDX, SpdxError> {
        let mut builder = Self::new();
        for atom in atoms {
            builder.process(atom)?;
        }
        Ok(builder.finish())
    }

    /// Close whatever section is open, committing its entity, and enter `next`.
    ///
    /// The only place an entity is committed, so no exit path can forget one.
    fn open_section(&mut self, next: Section) {
        match mem::replace(&mut self.section, next) {
            Section::Document => {}
            Section::Package(package) => self.packages.push(*package),
            Section::File(file) => self.files.push(*file),
            Section::Snippet(snippet) => self.snippets.push(*snippet),
            Section::OtherLicense(license) => self.other_licensing.push(*license),
        }
    }

    fn push_relationship(&mut self, relationship: Relationship) {
        if self.seen_relationships.insert(relationship.clone()) {
            self.relationships.push(relationship);
        }
    }

    /// Commit the annotation under construction once all five of its tags have been seen.
    fn flush_annotation(&mut self) {
        let AnnotationInProgress {
            annotator: Some(annotator),
            date: Some(date),
            comment: Some(comment),
            annotation_type: Some(annotation_type),
            spdxref: Some(spdxref),
        } = &self.annotation_in_progress
        else {
            return;
        };

        self.annotations.push(Annotation::new(
            annotator.clone(),
            *date,
            *annotation_type,
            Some(spdxref.clone()),
            comment.clone(),
        ));
        self.annotation_in_progress = AnnotationInProgress::default();
    }

    fn finish(mut self) -> SPDX {
        self.flush_annotation();
        self.open_section(Section::Document);
        if let Some(relationship) = self.relationship_in_progress.take() {
            self.push_relationship(relationship);
        }

        SPDX {
            document_creation_information: self.document_creation_information,
            package_information: self.packages,
            other_licensing_information_detected: self.other_licensing,
            file_information: self.files,
            snippet_information: self.snippets,
            relationships: self.relationships,
            annotations: self.annotations,
            // TODO: This should probably be removed.
            spdx_ref_counter: 0,
        }
    }

    // --- section accessors -------------------------------------------------------------
    //
    // A tag that appears outside its own section is dropped with a warning rather than
    // failing the document: SBOMs in the wild are frequently a little out of spec, and the
    // previous parser dropped these silently. Change these four functions to return an
    // error if the library should instead reject such documents.

    fn document(&mut self, atom: &Atom) -> Option<&mut DocumentCreationInformation> {
        if matches!(self.section, Section::Document) {
            Some(&mut self.document_creation_information)
        } else {
            warn!(
                "`{}` outside the document creation information section, ignoring",
                atom.as_ref()
            );
            None
        }
    }

    fn package(&mut self, atom: &Atom) -> Option<&mut PackageInformation> {
        if let Section::Package(package) = &mut self.section {
            Some(package)
        } else {
            warn!("`{}` outside a package section, ignoring", atom.as_ref());
            None
        }
    }

    fn file(&mut self, atom: &Atom) -> Option<&mut FileInformation> {
        if let Section::File(file) = &mut self.section {
            Some(file)
        } else {
            warn!("`{}` outside a file section, ignoring", atom.as_ref());
            None
        }
    }

    fn snippet(&mut self, atom: &Atom) -> Option<&mut Snippet> {
        if let Section::Snippet(snippet) = &mut self.section {
            Some(snippet)
        } else {
            warn!("`{}` outside a snippet section, ignoring", atom.as_ref());
            None
        }
    }

    fn other_license(&mut self, atom: &Atom) -> Option<&mut OtherLicensingInformationDetected> {
        if let Section::OtherLicense(license) = &mut self.section {
            Some(license)
        } else {
            warn!(
                "`{}` outside an extracted licensing information section, ignoring",
                atom.as_ref()
            );
            None
        }
    }

    /// Apply one atom.
    ///
    /// The match is deliberately exhaustive: adding a variant to [`Atom`] must not compile
    /// until it is handled here. Every field the tag-value parser used to drop on the floor
    /// was hidden behind a `_ => {}` arm.
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn process(&mut self, atom: &Atom) -> Result<(), SpdxError> {
        // An annotation is complete as soon as its fifth tag has been seen; check before
        // applying this atom so a following annotation starts from a clean slate.
        self.flush_annotation();

        match atom {
            // --- section openers -----------------------------------------------------
            Atom::PackageName(value) => {
                self.open_section(Section::Package(Box::new(PackageInformation {
                    package_name: value.clone(),
                    ..PackageInformation::default()
                })));
                // Belongs to the package that is opening; stays unset until its SPDXID is
                // seen so that a package without one cannot emit `CONTAINS` edges from a
                // nonexistent identifier.
                self.current_package_id = None;
            }
            Atom::FileName(value) => {
                self.open_section(Section::File(Box::new(FileInformation {
                    file_name: value.clone(),
                    ..FileInformation::default()
                })));
            }
            Atom::SnippetSPDXID(value) => {
                self.open_section(Section::Snippet(Box::new(Snippet {
                    snippet_spdx_identifier: value.clone(),
                    ..Snippet::default()
                })));
            }
            Atom::LicenseID(value) => {
                self.open_section(Section::OtherLicense(Box::new(
                    OtherLicensingInformationDetected {
                        license_identifier: value.clone(),
                        ..OtherLicensingInformationDetected::default()
                    },
                )));
            }

            // --- the one genuinely ambiguous tag -------------------------------------
            // `SPDXID` is the only tag shared between sections, so it is routed by the
            // cursor rather than guessed at from the state of the entity.
            Atom::SPDXID(value) => {
                let mut contained_by = None;
                match &mut self.section {
                    Section::Document => {
                        self.document_creation_information
                            .spdx_identifier
                            .clone_from(value);
                    }
                    Section::Package(package) => {
                        package.package_spdx_identifier.clone_from(value);
                        self.current_package_id = Some(value.clone());
                    }
                    Section::File(file) => {
                        file.file_spdx_identifier.clone_from(value);
                        contained_by.clone_from(&self.current_package_id);
                    }
                    Section::Snippet(_) | Section::OtherLicense(_) => {
                        warn!("`SPDXID` in a section that has no identifier, ignoring");
                    }
                }
                if let Some(package_id) = contained_by {
                    self.push_relationship(Relationship::new(
                        &package_id,
                        value,
                        RelationshipType::Contains,
                        None,
                    ));
                }
            }

            // --- document creation information ---------------------------------------
            Atom::SpdxVersion(value) => {
                if let Some(document) = self.document(atom) {
                    document.spdx_version.clone_from(value);
                }
            }
            Atom::DataLicense(value) => {
                if let Some(document) = self.document(atom) {
                    document.data_license.clone_from(value);
                }
            }
            Atom::DocumentName(value) => {
                if let Some(document) = self.document(atom) {
                    document.document_name.clone_from(value);
                }
            }
            Atom::DocumentNamespace(value) => {
                if let Some(document) = self.document(atom) {
                    document.spdx_document_namespace.clone_from(value);
                }
            }
            Atom::ExternalDocumentRef(value) => {
                if let Some(document) = self.document(atom) {
                    document.external_document_references.push(value.clone());
                }
            }
            Atom::LicenseListVersion(value) => {
                if let Some(document) = self.document(atom) {
                    document.creation_info.license_list_version = Some(value.clone());
                }
            }
            Atom::Creator(value) => {
                if let Some(document) = self.document(atom) {
                    document.creation_info.creators.push(value.clone());
                }
            }
            Atom::Created(value) => {
                let created = DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc);
                if let Some(document) = self.document(atom) {
                    document.creation_info.created = created;
                }
            }
            Atom::CreatorComment(value) => {
                if let Some(document) = self.document(atom) {
                    document.creation_info.creator_comment = Some(value.clone());
                }
            }
            Atom::DocumentComment(value) => {
                if let Some(document) = self.document(atom) {
                    document.document_comment = Some(value.clone());
                }
            }

            // --- package information --------------------------------------------------
            Atom::PackageVersion(value) => {
                if let Some(package) = self.package(atom) {
                    package.package_version = Some(value.clone());
                }
            }
            Atom::PackageFileName(value) => {
                if let Some(package) = self.package(atom) {
                    package.package_file_name = Some(value.clone());
                }
            }
            Atom::PackageSupplier(value) => {
                if let Some(package) = self.package(atom) {
                    package.package_supplier = Some(value.clone());
                }
            }
            Atom::PackageOriginator(value) => {
                if let Some(package) = self.package(atom) {
                    package.package_originator = Some(value.clone());
                }
            }
            Atom::PackageDownloadLocation(value) => {
                if let Some(package) = self.package(atom) {
                    package.package_download_location.clone_from(value);
                }
            }
            Atom::FilesAnalyzed(value) => {
                let files_analyzed = value.to_lowercase().parse().ok();
                if let Some(package) = self.package(atom) {
                    package.files_analyzed = files_analyzed;
                }
            }
            Atom::PackageVerificationCode(value) => {
                if let Some(package) = self.package(atom) {
                    package.package_verification_code = Some(value.clone());
                }
            }
            Atom::PackageChecksum(value) => {
                if let Some(package) = self.package(atom) {
                    package.package_checksum.push(value.clone());
                }
            }
            Atom::PackageHomePage(value) => {
                if let Some(package) = self.package(atom) {
                    package.package_home_page = Some(value.clone());
                }
            }
            Atom::PackageSourceInfo(value) => {
                if let Some(package) = self.package(atom) {
                    package.source_information = Some(value.clone());
                }
            }
            Atom::PackageLicenseConcluded(value) => {
                let license = SpdxExpression::parse(value)?;
                if let Some(package) = self.package(atom) {
                    package.concluded_license = Some(license);
                }
            }
            Atom::PackageLicenseInfoFromFiles(value) => {
                if let Some(package) = self.package(atom) {
                    package
                        .all_licenses_information_from_files
                        .push(value.clone());
                }
            }
            Atom::PackageLicenseDeclared(value) => {
                let license = SpdxExpression::parse(value)?;
                if let Some(package) = self.package(atom) {
                    package.declared_license = Some(license);
                }
            }
            Atom::PackageLicenseComments(value) => {
                if let Some(package) = self.package(atom) {
                    package.comments_on_license = Some(value.clone());
                }
            }
            Atom::PackageCopyrightText(value) => {
                if let Some(package) = self.package(atom) {
                    package.copyright_text = Some(value.clone());
                }
            }
            Atom::PackageSummary(value) => {
                if let Some(package) = self.package(atom) {
                    package.package_summary_description = Some(value.clone());
                }
            }
            Atom::PackageDescription(value) => {
                if let Some(package) = self.package(atom) {
                    package.package_detailed_description = Some(value.clone());
                }
            }
            Atom::PackageComment(value) => {
                if let Some(package) = self.package(atom) {
                    package.package_comment = Some(value.clone());
                }
            }
            Atom::PackageAttributionText(value) => {
                if let Some(package) = self.package(atom) {
                    package.package_attribution_text.push(value.clone());
                }
            }
            Atom::PrimaryPackagePurpose(value) => {
                if let Some(package) = self.package(atom) {
                    package.primary_package_purpose = Some(*value);
                }
            }
            Atom::BuiltDate(value) => {
                if let Some(package) = self.package(atom) {
                    package.built_date = Some(value.clone());
                }
            }
            Atom::ReleaseDate(value) => {
                if let Some(package) = self.package(atom) {
                    package.release_date = Some(value.clone());
                }
            }
            Atom::ValidUntilDate(value) => {
                if let Some(package) = self.package(atom) {
                    package.valid_until_date = Some(value.clone());
                }
            }
            // The reference is committed immediately and the comment amends it in place, so
            // there is no second piece of in-progress state that a section change could
            // forget to flush.
            Atom::ExternalRef(value) => {
                if let Some(package) = self.package(atom) {
                    package.external_reference.push(value.clone());
                }
            }
            Atom::ExternalRefComment(value) => {
                if let Some(package) = self.package(atom) {
                    if let Some(reference) = package.external_reference.last_mut() {
                        reference.reference_comment = Some(value.clone());
                    } else {
                        warn!("`ExternalRefComment` with no preceding `ExternalRef`, ignoring");
                    }
                }
            }

            // --- file information -----------------------------------------------------
            Atom::FileType(value) => {
                if let Some(file) = self.file(atom) {
                    file.file_type.push(*value);
                }
            }
            Atom::FileChecksum(value) => {
                if let Some(file) = self.file(atom) {
                    file.file_checksum.push(value.clone());
                }
            }
            Atom::LicenseConcluded(value) => {
                let license = SpdxExpression::parse(value)?;
                if let Some(file) = self.file(atom) {
                    file.concluded_license = Some(license);
                }
            }
            Atom::LicenseInfoInFile(value) => {
                let license = SpdxExpression::parse(value)?;
                if let Some(file) = self.file(atom) {
                    file.license_information_in_file.push(license);
                }
            }
            Atom::LicenseComments(value) => {
                if let Some(file) = self.file(atom) {
                    file.comments_on_license = Some(value.clone());
                }
            }
            Atom::FileCopyrightText(value) => {
                if let Some(file) = self.file(atom) {
                    file.copyright_text = Some(value.clone());
                }
            }
            Atom::FileComment(value) => {
                if let Some(file) = self.file(atom) {
                    file.file_comment = Some(value.clone());
                }
            }
            Atom::FileNotice(value) => {
                if let Some(file) = self.file(atom) {
                    file.file_notice = Some(value.clone());
                }
            }
            Atom::FileContributor(value) => {
                if let Some(file) = self.file(atom) {
                    file.file_contributor.push(value.clone());
                }
            }
            Atom::FileAttributionText(value) => {
                if let Some(file) = self.file(atom) {
                    file.file_attribution_text
                        .get_or_insert_with(Vec::new)
                        .push(value.clone());
                }
            }

            // --- snippet information --------------------------------------------------
            Atom::SnippetFromFileSPDXID(value) => {
                if let Some(snippet) = self.snippet(atom) {
                    snippet.snippet_from_file_spdx_identifier.clone_from(value);
                }
            }
            Atom::SnippetByteRange(value) => {
                if let Some(snippet) = self.snippet(atom) {
                    snippet.ranges.push(Range::new(
                        Pointer::new_byte(None, value.0),
                        Pointer::new_byte(None, value.1),
                    ));
                }
            }
            Atom::SnippetLineRange(value) => {
                if let Some(snippet) = self.snippet(atom) {
                    snippet.ranges.push(Range::new(
                        Pointer::new_line(None, value.0),
                        Pointer::new_line(None, value.1),
                    ));
                }
            }
            Atom::SnippetLicenseConcluded(value) => {
                let license = SpdxExpression::parse(value)?;
                if let Some(snippet) = self.snippet(atom) {
                    snippet.snippet_concluded_license = Some(license);
                }
            }
            Atom::LicenseInfoInSnippet(value) => {
                if let Some(snippet) = self.snippet(atom) {
                    snippet.license_information_in_snippet.push(value.clone());
                }
            }
            Atom::SnippetLicenseComments(value) => {
                if let Some(snippet) = self.snippet(atom) {
                    snippet.snippet_comments_on_license = Some(value.clone());
                }
            }
            Atom::SnippetCopyrightText(value) => {
                if let Some(snippet) = self.snippet(atom) {
                    snippet.snippet_copyright_text = Some(value.clone());
                }
            }
            Atom::SnippetComment(value) => {
                if let Some(snippet) = self.snippet(atom) {
                    snippet.snippet_comment = Some(value.clone());
                }
            }
            Atom::SnippetName(value) => {
                if let Some(snippet) = self.snippet(atom) {
                    snippet.snippet_name = Some(value.clone());
                }
            }
            Atom::SnippetAttributionText(value) => {
                if let Some(snippet) = self.snippet(atom) {
                    snippet.snippet_attribution_text = Some(value.clone());
                }
            }

            // --- other licensing information detected ---------------------------------
            Atom::ExtractedText(value) => {
                if let Some(license) = self.other_license(atom) {
                    license.extracted_text.clone_from(value);
                }
            }
            Atom::LicenseName(value) => {
                if let Some(license) = self.other_license(atom) {
                    license.license_name.clone_from(value);
                }
            }
            Atom::LicenseCrossReference(value) => {
                if let Some(license) = self.other_license(atom) {
                    license.license_cross_reference.push(value.clone());
                }
            }
            Atom::LicenseComment(value) => {
                if let Some(license) = self.other_license(atom) {
                    license.license_comment = Some(value.clone());
                }
            }

            // --- section-independent records ------------------------------------------
            Atom::Relationship(value) => {
                if let Some(previous) = self.relationship_in_progress.take() {
                    self.push_relationship(previous);
                }
                self.relationship_in_progress = Some(value.clone());
            }
            Atom::RelationshipComment(value) => {
                if let Some(relationship) = &mut self.relationship_in_progress {
                    relationship.comment = Some(value.clone());
                } else {
                    warn!("`RelationshipComment` with no preceding `Relationship`, ignoring");
                }
            }
            Atom::Annotator(value) => {
                self.annotation_in_progress.annotator = Some(value.clone());
            }
            Atom::AnnotationDate(value) => {
                self.annotation_in_progress.date =
                    Some(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc));
            }
            Atom::AnnotationType(value) => {
                self.annotation_in_progress.annotation_type = Some(*value);
            }
            Atom::SPDXREF(value) => {
                self.annotation_in_progress.spdxref = Some(value.clone());
            }
            Atom::AnnotationComment(value) => {
                self.annotation_in_progress.comment = Some(value.clone());
            }

            // Not part of the document.
            Atom::TVComment(_) => {}
        }

        Ok(())
    }
}
