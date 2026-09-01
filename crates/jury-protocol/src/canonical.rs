#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LengthOverflow;

pub(crate) fn jce_v1(domain: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(domain.len() + 3);
    output.extend_from_slice(domain.as_bytes());
    output.extend_from_slice(&[0, 0, 1]);
    output
}

pub(crate) fn u32be(value: usize) -> Result<[u8; 4], LengthOverflow> {
    u32::try_from(value)
        .map(u32::to_be_bytes)
        .map_err(|_| LengthOverflow)
}

pub(crate) fn bytes_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), LengthOverflow> {
    output.extend_from_slice(&u32be(value.len())?);
    output.extend_from_slice(value);
    Ok(())
}

pub(crate) fn list_bytes(output: &mut Vec<u8>, values: &[Vec<u8>]) -> Result<(), LengthOverflow> {
    output.extend_from_slice(&u32be(values.len())?);
    for value in values {
        bytes_field(output, value)?;
    }
    Ok(())
}

pub(crate) fn list_fixed<T>(
    output: &mut Vec<u8>,
    values: &[T],
    mut append: impl FnMut(&mut Vec<u8>, &T),
) -> Result<(), LengthOverflow> {
    output.extend_from_slice(&u32be(values.len())?);
    for value in values {
        append(output, value);
    }
    Ok(())
}

pub(crate) fn optional_fixed(output: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            output.extend_from_slice(value);
        }
    }
}

pub(crate) fn optional_bytes(
    output: &mut Vec<u8>,
    value: Option<&[u8]>,
) -> Result<(), LengthOverflow> {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            bytes_field(output, value)?;
        }
    }
    Ok(())
}

pub(crate) fn optional_u8(output: &mut Vec<u8>, value: Option<u8>) {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            output.push(value);
        }
    }
}

pub(crate) fn optional_u64(output: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_primitives_preserve_suite_and_length_encoding() -> Result<(), &'static str> {
        let mut output = jce_v1("jury-example");
        bytes_field(&mut output, b"ab").map_err(|_| "short field")?;
        list_bytes(&mut output, &[b"c".to_vec(), b"de".to_vec()]).map_err(|_| "short list")?;
        optional_fixed(&mut output, Some(b"f"));
        optional_bytes(&mut output, None).map_err(|_| "absent field")?;
        optional_u8(&mut output, Some(7));
        optional_u64(&mut output, Some(8));

        assert_eq!(
            output,
            b"jury-example\0\0\x01\0\0\0\x02ab\0\0\0\x02\0\0\0\x01c\0\0\0\x02de\x01f\0\x01\x07\x01\0\0\0\0\0\0\0\x08"
        );
        Ok(())
    }
}
