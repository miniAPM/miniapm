use super::*;

#[test]
fn percentiles_pick_the_nearest_rank() {
    for (n, percent, expected) in [
        (1, 95, 1),
        (3, 95, 3),
        (4, 50, 2),
        (20, 95, 19),
        (32, 95, 31),
        (100, 95, 95),
        (100, 99, 99),
        (101, 99, 100),
    ] {
        let sorted: Vec<f64> = (1..=n).map(f64::from).collect();
        assert_eq!(
            percentile_ms(&sorted, percent),
            i64::from(expected),
            "n={n} p{percent}"
        );
    }
}
