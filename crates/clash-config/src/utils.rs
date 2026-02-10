// Utility functions for YAML deserialization

use serde::Deserialize;
use std::fmt::Display;
use std::str::FromStr;

/// Deserialize a value that can be either a string or a number
pub fn deserialize_u64<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromStr + serde::Deserialize<'de>,
    <T as FromStr>::Err: Display,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNum<T> {
        String(String),
        Num(T),
    }

    match StringOrNum::<T>::deserialize(deserializer)? {
        StringOrNum::String(s) => s.parse().map_err(serde::de::Error::custom),
        StringOrNum::Num(n) => Ok(n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[test]
    fn test_deserialize_u64_from_number() {
        #[derive(Deserialize)]
        struct Test {
            #[serde(deserialize_with = "deserialize_u64")]
            value: u64,
        }

        let yaml = r#"value: 12345"#;
        let result: Test = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(result.value, 12345);
    }

    #[test]
    fn test_deserialize_u64_from_string() {
        #[derive(Deserialize)]
        struct Test {
            #[serde(deserialize_with = "deserialize_u64")]
            value: u64,
        }

        let yaml = r#"value: "12345""#;
        let result: Test = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(result.value, 12345);
    }
}
