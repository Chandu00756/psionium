/// A Unix timestamp as a `YYYY-MM-DD` UTC date.
pub(crate) fn date(timestamp: i64) -> String {
    let (y, m, d) = civil(timestamp.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// A Unix timestamp as an RFC 3339 UTC time.
pub(crate) fn rfc3339(timestamp: i64) -> String {
    let (y, m, d) = civil(timestamp.div_euclid(86_400));
    let secs = timestamp.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    #[test]
    fn dates() {
        assert_eq!(super::date(0), "1970-01-01");
        assert_eq!(super::date(1_798_761_600), "2027-01-01");
        assert_eq!(super::date(951_782_400), "2000-02-29");
        assert_eq!(super::rfc3339(1_798_761_661), "2027-01-01T00:01:01Z");
    }
}
