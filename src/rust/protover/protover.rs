// Copyright (c) 2016-2017, The Tor Project, Inc. */
// See LICENSE for licensing information */

use std::collections::HashMap;
use std::ffi::CStr;
use std::fmt;
use std::str;
use std::str::FromStr;
use std::string::String;
use std::u32;

use tor_log::{LogSeverity, LogDomain};
use external::c_tor_version_as_new_as;

use errors::ProtoverError;
use protoset::Version;
use protoset::ProtoSet;

/// The first version of Tor that included "proto" entries in its descriptors.
/// Authorities should use this to decide whether to guess proto lines.
///
/// C_RUST_COUPLED:
///     src/or/protover.h `FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS`
const FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS: &'static str = "0.2.9.3-alpha";

/// The maximum number of subprotocol version numbers we will attempt to expand
/// before concluding that someone is trying to DoS us
///
/// C_RUST_COUPLED: src/or/protover.c `MAX_PROTOCOLS_TO_EXPAND`
pub(crate) const MAX_PROTOCOLS_TO_EXPAND: usize = (1<<16);

/// Known subprotocols in Tor. Indicates which subprotocol a relay supports.
///
/// C_RUST_COUPLED: src/or/protover.h `protocol_type_t`
#[derive(Hash, Eq, PartialEq, Debug)]
pub enum Protocol {
    Cons,
    Desc,
    DirCache,
    HSDir,
    HSIntro,
    HSRend,
    Link,
    LinkAuth,
    Microdesc,
    Relay,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Translates a string representation of a protocol into a Proto type.
/// Error if the string is an unrecognized protocol name.
///
/// C_RUST_COUPLED: src/or/protover.c `PROTOCOL_NAMES`
impl FromStr for Protocol {
    type Err = ProtoverError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Cons" => Ok(Protocol::Cons),
            "Desc" => Ok(Protocol::Desc),
            "DirCache" => Ok(Protocol::DirCache),
            "HSDir" => Ok(Protocol::HSDir),
            "HSIntro" => Ok(Protocol::HSIntro),
            "HSRend" => Ok(Protocol::HSRend),
            "Link" => Ok(Protocol::Link),
            "LinkAuth" => Ok(Protocol::LinkAuth),
            "Microdesc" => Ok(Protocol::Microdesc),
            "Relay" => Ok(Protocol::Relay),
            _ => Err(ProtoverError::UnknownProtocol),
        }
    }
}

/// Get a CStr representation of current supported protocols, for
/// passing to C, or for converting to a `&str` for Rust.
///
/// # Returns
///
/// An `&'static CStr` whose value is the existing protocols supported by tor.
/// Returned data is in the format as follows:
///
/// "HSDir=1-1 LinkAuth=1"
///
/// # Note
///
/// Rust code can use the `&'static CStr` as a normal `&'a str` by
/// calling `protover::get_supported_protocols`.
///
//  C_RUST_COUPLED: src/or/protover.c `protover_get_supported_protocols`
pub(crate) fn get_supported_protocols_cstr() -> &'static CStr {
    cstr!("Cons=1-2 \
           Desc=1-2 \
           DirCache=1-2 \
           HSDir=1-2 \
           HSIntro=3-4 \
           HSRend=1-2 \
           Link=1-5 \
           LinkAuth=1,3 \
           Microdesc=1-2 \
           Relay=1-2")
}

/// A map of protocol names to the versions of them which are supported.
pub struct Protover(HashMap<Protocol, ProtoSet>);

impl Protover {
    pub fn from_proto_entries<I, S>(protocol_strs: I) -> Result<Self, ProtoverError>
        where I: Iterator<Item = S>,
              S: AsRef<str>,
    {
        let mut parsed = HashMap::new();
        for subproto in protocol_strs {
            let (name, version) = get_proto_and_vers(subproto.as_ref())?;
            parsed.insert(name, version);
        }
        Ok(Protover(parsed))
    }

    /// Translates a string representation of a protocol list to a
    /// Protover instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use protover::Protover;
    ///
    /// let supported_protocols = Protover::from_proto_entries_string(
    ///     "HSDir=1-2 HSIntro=3-4"
    /// );
    /// ```
    pub fn from_proto_entries_string(proto_entries: &str) -> Result<Self, ProtoverError> {
        Self::from_proto_entries(proto_entries.split(' '))
    }

    /// Translate the supported tor versions from a string into a
    /// HashMap, which is useful when looking up a specific
    /// subprotocol.
    ///
    fn supported() -> Result<Self, ProtoverError> {
        let supported_cstr: &'static CStr = get_supported_protocols_cstr();
        let supported: &str = match supported_cstr.to_str() {
            Ok(x)  => x,
            Err(_) => "",
        };

        Self::from_proto_entries_string(supported)
    }
}

/// Parse the subprotocol type and its version numbers.
///
/// # Inputs
///
/// * A `protocol_entry` string, comprised of a keyword, an "=" sign, and one
/// or more version numbers.
///
/// # Returns
///
/// A `Result` whose `Ok` value is a tuple of `(Proto, HashSet<u32>)`, where the
/// first element is the subprotocol type (see `protover::Proto`) and the last
/// element is a(n unordered) set of unique version numbers which are supported.
/// Otherwise, the `Err` value of this `Result` is a description of the error
fn get_proto_and_vers<'a>(protocol_entry: &'a str) -> Result<(Protocol, ProtoSet), ProtoverError> {
    let mut parts = protocol_entry.splitn(2, '=');

    let proto = match parts.next() {
        Some(n) => n,
        None => return Err(ProtoverError::Unparseable),
    };

    let vers = match parts.next() {
        Some(n) => n,
        None => return Err(ProtoverError::Unparseable),
    };

    let versions: ProtoSet = vers.parse()?;
    let proto_name: Protocol = proto.parse()?;

    Ok((proto_name, versions))
}

/// Parses a single subprotocol entry string into subprotocol and version
/// parts, and then checks whether any of those versions are unsupported.
/// Helper for protover::all_supported
///
/// # Inputs
///
/// Accepted data is in the string format as follows:
///
/// "HSDir=1-1"
///
/// # Returns
///
/// Returns `true` if the protocol entry is well-formatted and only contains
/// versions that are also supported in tor. Otherwise, returns false
fn contains_only_supported_protocols(proto_entry: &str) -> bool {
    let (name, mut vers) = match get_proto_and_vers(proto_entry) {
        Ok(n) => n,
        Err("Too many versions to expand") => {
            tor_log_msg!(
                LogSeverity::Warn,
                LogDomain::Net,
                "get_versions",
                "When expanding a protocol list from an authority, I \
                got too many protocols. This is possibly an attack or a bug, \
                unless the Tor network truly has expanded to support over {} \
                different subprotocol versions. The offending string was: {}",
                MAX_PROTOCOLS_TO_EXPAND,
                proto_entry
            );
            return false;
        }
        Err(_) => return false,
    };

    let currently_supported = match Protover::supported() {
        Ok(n) => n.0,
        Err(_) => return false,
    };

    let supported_versions = match currently_supported.get(&name) {
        Some(n) => n,
        None => return false,
    };

    vers.retain(|x| !supported_versions.contains(x));
    vers.is_empty()
}

/// Determine if we support every protocol a client supports, and if not,
/// determine which protocols we do not have support for.
///
/// # Inputs
///
/// Accepted data is in the string format as follows:
///
/// "HSDir=1-1 LinkAuth=1-2"
///
/// # Returns
///
/// Return `true` if every protocol version is one that we support.
/// Otherwise, return `false`.
/// Optionally, return parameters which the client supports but which we do not
///
/// # Examples
/// ```
/// use protover::all_supported;
///
/// let (is_supported, unsupported)  = all_supported("Link=1");
/// assert_eq!(true, is_supported);
///
/// let (is_supported, unsupported)  = all_supported("Link=5-6");
/// assert_eq!(false, is_supported);
/// assert_eq!("Link=5-6", unsupported);
/// ```
pub fn all_supported(protocols: &str) -> (bool, String) {
    let unsupported = protocols
        .split_whitespace()
        .filter(|v| !contains_only_supported_protocols(v))
        .collect::<Vec<&str>>();

    (unsupported.is_empty(), unsupported.join(" "))
}

/// Return true iff the provided protocol list includes support for the
/// indicated protocol and version.
/// Otherwise, return false
///
/// # Inputs
///
/// * `list`, a string representation of a list of protocol entries.
/// * `proto`, a `Proto` to test support for
/// * `vers`, a `Version` version which we will go on to determine whether the
/// specified protocol supports.
///
/// # Examples
/// ```
/// use protover::*;
///
/// let is_supported = protover_string_supports_protocol("Link=3-4 Cons=1",
///                                                      Proto::Cons,1);
/// assert_eq!(true, is_supported);
///
/// let is_not_supported = protover_string_supports_protocol("Link=3-4 Cons=1",
///                                                           Proto::Cons,5);
/// assert_eq!(false, is_not_supported)
/// ```
pub fn protover_string_supports_protocol(list: &str, proto: Protocol, vers: Version) -> bool {
    let supported = match Protover::from_proto_entries_string(list) {
        Ok(result) => result.0,
        Err(_) => return false,
    };

    let supported_versions = match supported.get(&proto) {
        Some(n) => n,
        None => return false,
    };

    supported_versions.contains(&vers)
}

/// As protover_string_supports_protocol(), but also returns True if
/// any later version of the protocol is supported.
///
/// # Examples
/// ```
/// use protover::*;
///
/// let is_supported = protover_string_supports_protocol_or_later(
///                       "Link=3-4 Cons=5", Proto::Cons, 5);
///
/// assert_eq!(true, is_supported);
///
/// let is_supported = protover_string_supports_protocol_or_later(
///                       "Link=3-4 Cons=5", Proto::Cons, 4);
///
/// assert_eq!(true, is_supported);
///
/// let is_supported = protover_string_supports_protocol_or_later(
///                       "Link=3-4 Cons=5", Proto::Cons, 6);
///
/// assert_eq!(false, is_supported);
/// ```
pub fn protover_string_supports_protocol_or_later(
    list: &str,
    proto: Proto,
    vers: u32,
) -> bool {
    let supported = match Protover::from_proto_entries_string(list) {
        Ok(result) => result.0,
        Err(_) => return false,
    };

    let supported_versions = match supported.get(&proto) {
        Some(n) => n,
        None => return false,
    };

    supported_versions.iter().any(|v| v >= &vers)
}

/// Parses a protocol list without validating the protocol names
///
/// # Inputs
///
/// * `protocol_string`, a string comprised of keys and values, both which are
/// strings. The keys are the protocol names while values are a string
/// representation of the supported versions.
///
/// The input is _not_ expected to be a subset of the Proto types
///
/// # Returns
///
/// A `Result` whose `Ok` value is a `ProtoSet` holding all of the
/// unique version numbers.
///
/// The returned `Result`'s `Err` value is an `ProtoverError` whose `Display`
/// impl has a description of the error.
///
/// # Errors
///
/// This function will error if:
///
/// * The protocol string does not follow the "protocol_name=version_list"
///   expected format, or
/// * If the version string is malformed. See `impl FromStr for ProtoSet`.
fn parse_protocols_from_string_with_no_validation(protocol_string: &str) -> Result<ProtoSet, ProtoverError> {
    let mut parsed: Protover = Protover::default();

    for subproto in protocol_string.split(' ') {
        let mut parts = subproto.splitn(2, '=');

        let name = match parts.next() {
            Some("") => return Err(ProtoverError::Unparseable),
            Some(n) => n,
            None => return Err(ProtoverError::Unparseable),
        };

        let vers = match parts.next() {
            Some(n) => n,
            None => return Err(ProtoverError::Unparseable),
        };

        let versions = ProtoSet::from_str(vers)?;

        parsed.insert(String::from(name), versions);
    }
    Ok(parsed)
}

/// Protocol voting implementation.
///
/// Given a list of strings describing protocol versions, return a new
/// string encoding all of the protocols that are listed by at
/// least threshold of the inputs.
///
/// The string is sorted according to the following conventions:
///   - Protocols names are alphabetized
///   - Protocols are in order low to high
///   - Individual and ranges are listed together. For example,
///     "3, 5-10,13"
///   - All entries are unique
///
/// # Examples
///
/// ```
/// use protover::compute_vote;
///
/// let protos = vec![String::from("Link=3-4"), String::from("Link=3")];
/// let vote = compute_vote(protos, 2);
/// assert_eq!("Link=3", vote)
/// ```
pub fn compute_vote(
    list_of_proto_strings: Vec<String>,
    threshold: i32,
) -> String {
    let empty = String::from("");

    if list_of_proto_strings.is_empty() {
        return empty;
    }

    // all_count is a structure to represent the count of the number of
    // supported versions for a specific protocol. For example, in JSON format:
    // {
    //  "FirstSupportedProtocol": {
    //      "1": "3",
    //      "2": "1"
    //  }
    // }
    // means that FirstSupportedProtocol has three votes which support version
    // 1, and one vote that supports version 2
    let mut all_count: HashMap<String, HashMap<Version, usize>> =
        HashMap::new();

    // parse and collect all of the protos and their versions and collect them
    for vote in list_of_proto_strings {
        let this_vote: HashMap<String, Versions> =
            match parse_protocols_from_string_with_no_validation(&vote) {
                Ok(result) => result,
                Err(_) => continue,
            };
        for (protocol, versions) in this_vote {
            let supported_vers: &mut HashMap<Version, usize> =
                all_count.entry(protocol).or_insert(HashMap::new());

            for version in versions.0 {
                let counter: &mut usize =
                    supported_vers.entry(version).or_insert(0);
                *counter += 1;
            }
        }
    }

    let mut final_output: HashMap<String, String> =
        HashMap::with_capacity(get_supported_protocols().split(" ").count());

    // Go through and remove verstions that are less than the threshold
    for (protocol, versions) in all_count {
        let mut meets_threshold = Vec::new();
        for (version, count) in versions {
            if count >= threshold as usize {
                meets_threshold.insert(version);
            }
        }

        // For each protocol, compress its version list into the expected
        // protocol version string format
        let contracted = contract_protocol_list(&meets_threshold);
        if !contracted.is_empty() {
            final_output.insert(protocol, contracted);
        }
    }

    write_vote_to_string(&final_output)
}

/// Return a String comprised of protocol entries in alphabetical order
///
/// # Inputs
///
/// * `vote`, a `HashMap` comprised of keys and values, both which are strings.
/// The keys are the protocol names while values are a string representation of
/// the supported versions.
///
/// # Returns
///
/// A `String` whose value is series of pairs, comprising of the protocol name
/// and versions that it supports. The string takes the following format:
///
/// "first_protocol_name=1,2-5, second_protocol_name=4,5"
///
/// Sorts the keys in alphabetical order and creates the expected subprotocol
/// entry format.
///
fn write_vote_to_string(vote: &HashMap<String, String>) -> String {
    let mut keys: Vec<&String> = vote.keys().collect();
    keys.sort();

    let mut output = Vec::new();
    for key in keys {
        // TODO error in indexing here?
        output.push(format!("{}={}", key, vote[key]));
    }
    output.join(" ")
}

/// Returns a boolean indicating whether the given protocol and version is
/// supported in any of the existing Tor protocols
///
/// # Examples
/// ```
/// use protover::*;
///
/// let is_supported = is_supported_here(Proto::Link, 10);
/// assert_eq!(false, is_supported);
///
/// let is_supported = is_supported_here(Proto::Link, 1);
/// assert_eq!(true, is_supported);
/// ```
pub fn is_supported_here(proto: Proto, vers: Version) -> bool {
    let currently_supported = match Protover::tor_supported() {
        Ok(result) => result.0,
        Err(_) => return false,
    };

    let supported_versions = match currently_supported.get(&proto) {
        Some(n) => n,
        None => return false,
    };

    supported_versions.0.contains(&vers)
}

/// Older versions of Tor cannot infer their own subprotocols
/// Used to determine which subprotocols are supported by older Tor versions.
///
/// # Inputs
///
/// * `version`, a string comprised of "[0-9a-z.-]"
///
/// # Returns
///
/// A `&'static CStr` encoding a list of protocol names and supported
/// versions. The string takes the following format:
///
/// "HSDir=1-1 LinkAuth=1"
///
/// This function returns the protocols that are supported by the version input,
/// only for tor versions older than FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS.
///
/// C_RUST_COUPLED: src/rust/protover.c `compute_for_old_tor`
pub fn compute_for_old_tor(version: &str) -> &'static CStr {
    let empty: &'static CStr = cstr!("");

    if c_tor_version_as_new_as(version, FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS) {
        return empty;
    }

    if c_tor_version_as_new_as(version, "0.2.9.1-alpha") {
        return cstr!("Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1-2 \
                      Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2");
    }

    if c_tor_version_as_new_as(version, "0.2.7.5") {
        return cstr!("Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 \
                      Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2");
    }

    if c_tor_version_as_new_as(version, "0.2.4.19") {
        return cstr!("Cons=1 Desc=1 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 \
                      Link=1-4 LinkAuth=1 Microdesc=1 Relay=1-2");
    }

    empty
}

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use std::string::ToString;

    use super::*;

    #[test]
    fn test_versions_from_str() {
        use std::collections::HashSet;

        assert_eq!(Err("invalid protocol entry"), Versions::from_str("a,b"));
        assert_eq!(Err("invalid protocol entry"), Versions::from_str("1,!"));

        {
            let mut versions: HashSet<Version> = HashSet::new();
            versions.insert(1);
            assert_eq!(versions, Versions::from_str("1").unwrap());
        }
        {
            let mut versions: HashSet<Version> = HashSet::new();
            versions.insert(1);
            versions.insert(2);
            assert_eq!(versions, Versions::from_str("1,2").unwrap());
        }
        {
            let mut versions: HashSet<Version> = HashSet::new();
            versions.insert(1);
            versions.insert(2);
            versions.insert(3);
            assert_eq!(versions, Versions::from_str("1-3").unwrap());
        }
        {
            let mut versions: HashSet<Version> = HashSet::new();
            versions.insert(1);
            versions.insert(2);
            versions.insert(5);
            assert_eq!(versions, Versions::from_str("1-2,5").unwrap());
        }
        {
            let mut versions = Versions::default();
            versions.insert(1);
            versions.insert(3);
            versions.insert(4);
            versions.insert(5);

            assert_eq!(versions, Versions::from_str("1,3-5").unwrap());
        }
    }

    #[test]
    fn test_contains_only_supported_protocols() {
        use super::contains_only_supported_protocols;

        assert_eq!(false, contains_only_supported_protocols(""));
        assert_eq!(true, contains_only_supported_protocols("Cons="));
        assert_eq!(true, contains_only_supported_protocols("Cons=1"));
        assert_eq!(false, contains_only_supported_protocols("Cons=0"));
        assert_eq!(false, contains_only_supported_protocols("Cons=0-1"));
        assert_eq!(false, contains_only_supported_protocols("Cons=5"));
        assert_eq!(false, contains_only_supported_protocols("Cons=1-5"));
        assert_eq!(false, contains_only_supported_protocols("Cons=1,5"));
        assert_eq!(false, contains_only_supported_protocols("Cons=5,6"));
        assert_eq!(false, contains_only_supported_protocols("Cons=1,5,6"));
        assert_eq!(true, contains_only_supported_protocols("Cons=1,2"));
        assert_eq!(true, contains_only_supported_protocols("Cons=1-2"));
    }

    #[test]
    fn test_contract_protocol_list() {
        let mut versions = "";
        assert_eq!(String::from(versions), ProtoSet::from_str(&versions).to_string());

        versions = "1";
        assert_eq!(String::from(versions), ProtoSet::from_str(&versions).to_string());

        versions = "1-2";
        assert_eq!(String::from(versions), ProtoSet::from_str(&versions).to_string());

        versions = "1,3";
        assert_eq!(String::from(versions), ProtoSet::from_str(&versions).to_string());

        versions = "1-4";
        assert_eq!(String::from(versions), ProtoSet::from_str(&versions).to_string());

        versions = "1,3,5-7";
        assert_eq!(String::from(versions), ProtoSet::from_str(&versions).to_string());

        versions = "1-3,500";
        assert_eq!(String::from(versions), ProtoSet::from_str(&versions).to_string());
    }
}
