mod combinable;

use chrono::{DateTime, Utc};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::hash::Hash;
use std::{fs, io};
use std::io::Write;
use std::path::PathBuf;
use anyhow::{bail, Result};
use combinable::Combinable;

/// Merge 2 SBOMs (SPDX 2.3)
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Paths {
    /// Path of the first SBOM file
    pub path1: std::path::PathBuf,

    /// Path of the second SBOM file
    pub path2: std::path::PathBuf
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]	

pub struct Sbom {
    #[serde(rename = "SPDXID")]
    pub spdxid: String,
    pub spdx_version: String,
    pub data_license: String,
    pub creation_info: CreationInfo,
    pub document_namespace: String,
    pub name: String,
    pub packages: HashSet<Package>,
    pub relationships: HashSet<Relationship>,
    pub comment: Option<String>,
    pub external_document_refs: Option<HashSet<ExternalDocumentRef>>,
    pub has_extracted_licensing_infos: Option<HashSet<HasExtractedLicensingInfo>>,
    pub annotations: Option<HashSet<Annotation>>,
    pub document_describes: Option<HashSet<String>>,
    pub files: Option<HashSet<File>>,
    pub snippets: Option<HashSet<Snippet>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreationInfo {
    #[serde(default)]
    pub created: DateTime<Utc>,
    #[serde(default)]
    pub creators: HashSet<String>,
    pub comment: Option<String>,    
    pub license_list_version: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct ExternalDocumentRef {
    #[serde(default)]
    pub external_document_id: String,
    #[serde(default)]
    pub checksum: Checksum,
    #[serde(default)]
    pub spdx_document: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Checksum {
    #[serde(default)]
    pub algorithm: String,
    #[serde(default)]
    pub checksum_value: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct HasExtractedLicensingInfo {
    #[serde(default)]
    pub license_id: String,
    #[serde(default)]
    pub extracted_text: String,
    pub comment: Option<String>,
    pub name: Option<String>,
    #[serde(default)]
    pub see_alsos: Option<Vec<String>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Annotation {
    #[serde(default)]
    pub annotation_date: DateTime<Utc>,
    #[serde(default)]
    pub annotation_type: String,
    pub annotator: Option<String>,
    pub comment: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Package {
    #[serde(rename = "SPDXID")]
    pub spdxid: String,
    #[serde(default)]
    pub supplier: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version_info: String,
    #[serde(default)]
    pub annotations: BTreeSet<Annotation>,
    #[serde(default)]
    pub attribution_texts: Vec<String>,
    pub built_date: Option<String>,
    #[serde(default)]
    pub checksums: BTreeSet<Checksum>,
    #[serde(default)]
    pub download_location: String,
    #[serde(default)]
    pub external_refs: BTreeSet<ExternalRef>,    
    #[serde(default)]
    pub files_analyzed: bool,
    #[serde(default)]
    pub has_files: BTreeSet<String>,
    pub copyright_text: Option<String>,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub license_comments: Option<String>,
    pub license_concluded: Option<String>,
    pub license_declared: Option<String>,
    pub license_info_from_files: Option<BTreeSet<String>>,
    pub originator: Option<String>,
    pub package_file_name: Option<String>,
    pub package_verification_code: Option<PackageVerificationCode>,
    pub primary_package_purpose: Option<String>,
    pub release_date: Option<String>,
    pub source_info: Option<String>,
    pub summary: Option<String>,
    pub valid_until_date: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ExternalRef {    
    #[serde(default)]
    pub reference_category: String,
    #[serde(default)]
    pub reference_locator: String,
    #[serde(default)]
    pub reference_type: String,
    pub comment: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct PackageVerificationCode {
    #[serde(default)]
    pub package_verification_code_value: String,
    pub package_verification_code_excluded_files: Option<Vec<String>>,    
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct File {
    #[serde(rename = "SPDXID")]
    pub spdxid: String,
    #[serde(default)]
    pub checksums: Vec<Checksum>,
    #[serde(default)]
    pub file_contributors: BTreeSet<String>,
    #[serde(default)]
    pub file_name: String,
    pub copyright_text: Option<String>,
    pub file_types: Option<BTreeSet<String>>,
    pub license_concluded: Option<String>,
    pub license_info_in_files: Option<BTreeSet<String>>,
    pub comment: Option<String>,
    pub notice_text: Option<String>,
    pub license_comments: Option<String>,
    pub annotations: Option<Vec<Annotation>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Snippet {
    #[serde(rename = "SPDXID")]
    pub spdxid: String,   
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub copyright_text: String,
    #[serde(default)]
    pub license_comments: String,
    #[serde(default)]
    pub license_concluded: String,
    #[serde(default)]
    pub license_info_in_snippets: BTreeSet<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub ranges: Vec<Range>,
    #[serde(default)]
    pub snippet_from_file: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Range {
    #[serde(default)]
    pub end_pointer: EndPointer,
    #[serde(default)]
    pub start_pointer: StartPointer,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct EndPointer {
    #[serde(default)]
    pub reference: String,
    pub offset: Option<i64>,
    pub line_number: Option<i64>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct StartPointer {
    #[serde(default)]
    pub reference: String,
    pub offset: Option<i64>,
    pub line_number: Option<i64>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Relationship {
    #[serde(default)]
    pub spdx_element_id: String,
    #[serde(default)]
    pub relationship_type: String,
    #[serde(default)]
    pub related_spdx_element: String,
}

pub fn json_to_sbom(filepath: &PathBuf) -> Result<Sbom> {
   
    // TODO: use BufReader instead of read_to_string?
    let json = fs::read_to_string(&filepath).unwrap();

    let sbom: Sbom = serde_json::from_str(&json)?;
    
    Ok(sbom)
}

pub fn sbom_to_string(sbom: &Sbom) -> Result<String> {

    let merged = serde_json::to_string_pretty(&sbom)?;

    Ok(merged)
}

fn merge(sbom1: &Sbom, sbom2:&Sbom) -> Result<Sbom> {
    const VERSION: &str = "SPDX-2.3";
    if sbom1.spdx_version != VERSION || sbom2.spdx_version != VERSION {
        bail!("Version mismatch: SPDX version in both files must be {}", VERSION);
    }

    let s1 = sbom1.clone();
    let s2 = sbom2.clone();

    let mut all_creators = s1.creation_info.creators.combine(s2.creation_info.creators);
    all_creators.insert(String::from("Tool: Guardian.com-Merge-SBOM"));

    
    let merged: Sbom = Sbom { 
        spdxid: s1.spdxid, 
        spdx_version: s1.spdx_version, 
        creation_info: CreationInfo {
            license_list_version: s1.creation_info.license_list_version.combine(s2.creation_info.license_list_version),
            created: Utc::now(),
            creators: all_creators, 
            comment: s1.creation_info.comment.combine(s2.creation_info.comment)
        }, 
        name: format!("{} AND {}", s1.name, s2.name), 
        data_license: s1.data_license.combine(sbom2.clone().data_license), 
        comment: s1.comment.combine(s2.comment),
        external_document_refs: s1.external_document_refs.combine(s2.external_document_refs),
        has_extracted_licensing_infos: s1.has_extracted_licensing_infos.combine(s2.has_extracted_licensing_infos),
        annotations: s1.annotations.combine(s2.annotations),
        document_describes: s1.document_describes.combine(s2.document_describes),
        document_namespace: s1.document_namespace.combine(s2.document_namespace), 
        packages: s1.packages.combine(s2.packages),
        files: s1.files.combine(s2.files),
        relationships: s1.relationships.combine(s2.relationships),
        snippets: s1.snippets.combine(s2.snippets), 
    };
    Ok(merged)    
}

pub fn merge_all(file_paths: &Paths) -> Result<()>{

    let path1 = &file_paths.path1;
    let path2 = &file_paths.path2;

    let sbom1 = json_to_sbom(&path1).unwrap();
    let sbom2 = json_to_sbom(&path2).unwrap();

    let sbom_final = merge(&sbom1, &sbom2);

    let merged = sbom_to_string(&sbom_final?).unwrap();

    let stdout = io::stdout();
    let mut handle = stdout.lock();
    writeln!(handle, "{}", merged)?;

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
    #[test]
    fn merge_hashsets_works() {
        let mut hash1 = HashSet::new();

        hash1.insert("To Kill a Mockingbird".to_string());
        hash1.insert("The Odyssey".to_string());
        hash1.insert("The Great Gatsby".to_string());

        let mut hash2 = HashSet::new();
        hash2.insert("To Kill a Mockingbird".to_string());
        hash2.insert("A Dance With Dragons".to_string());

        let mut expected = HashSet::new();
        expected.insert("To Kill a Mockingbird".to_string());
        expected.insert("The Odyssey".to_string());
        expected.insert("The Great Gatsby".to_string());
        expected.insert("A Dance With Dragons".to_string());


        assert_eq!(expected, hash1.combine(hash2));
    }

    #[test]
    fn  merge_option_hashsets_works() {
        let mut hash1 = HashSet::new();

        hash1.insert("To Kill a Mockingbird".to_string());
        hash1.insert("The Odyssey".to_string());
        hash1.insert("The Great Gatsby".to_string());

        let hash1_option = Some(hash1.clone());

        let mut hash2 = HashSet::new();
        hash2.insert("To Kill a Mockingbird".to_string());
        hash2.insert("A Dance With Dragons".to_string());

        let hash2_option = Some(hash2.clone());

        let mut expected = HashSet::new();
        expected.insert("To Kill a Mockingbird".to_string());
        expected.insert("The Odyssey".to_string());
        expected.insert("The Great Gatsby".to_string());
        expected.insert("A Dance With Dragons".to_string());

        let expected_option = Some(expected.clone());

        assert_eq!(expected_option, hash1_option.combine(hash2_option));

    }

    #[test]
    fn  merge_option_hashsets_works_with_none() {
        let mut hash1 = HashSet::new();

        hash1.insert("To Kill a Mockingbird".to_string());
        hash1.insert("The Odyssey".to_string());
        hash1.insert("The Great Gatsby".to_string());

        let hash1_option = Some(hash1.clone());

        let hash2_option = None;

        let mut expected = HashSet::new();
        expected.insert("To Kill a Mockingbird".to_string());
        expected.insert("The Odyssey".to_string());
        expected.insert("The Great Gatsby".to_string());

        let expected_option = Some(expected.clone());

        assert_eq!(expected_option, hash1_option.combine(hash2_option));

    }

    #[test]

    fn  merge_option_hashsets_works_with_two_nones() {

        let hash1_option: Option<HashSet<String>> = None;

        let hash2_option: Option<HashSet<String>> = None;

        let expected_option: Option<HashSet<String>> = None;

        assert_eq!(expected_option, hash1_option.combine(hash2_option));

    }

    #[test]
    fn combine_option_strings_works() {
        let string1_option = Some(String::from("First string"));
        let string2_option = Some(String::from("Second string"));
        let expected = Some(String::from("First string AND Second string"));
        assert_eq!(expected, string1_option.combine(string2_option));
    }

    #[test]
    fn combine_option_strings_works_empty_string() {
        let string1_option: Option<String> = None;
        let string2_option = Some(String::from("Second string"));
        let expected = Some(String::from("Second string"));
        assert_eq!(expected, string1_option.combine(string2_option));
    }
}
