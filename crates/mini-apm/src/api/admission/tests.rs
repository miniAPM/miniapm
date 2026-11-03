use super::*;

#[test]
fn validates_budget_bounds() {
    for rate in [f64::NAN, f64::INFINITY, 0.0, -1.0, 1e-10, 1e10] {
        assert!(AdmissionConfig::new(rate, 1, 1).is_err());
    }
    assert!(AdmissionConfig::new(1.0, 0, 1).is_err());
    assert!(AdmissionConfig::new(1.0, 1_000_001, 1).is_err());
    assert!(AdmissionConfig::new(1.0, 1, 0).is_err());
    assert!(AdmissionConfig::new(1.0, 1, 65_537).is_err());
}

#[test]
fn shared_budget_recovers_without_sleeping() {
    let config = AdmissionConfig::new(2.0, 2, 4096).unwrap();
    let admission = Admission::new(Some(&config), None);
    let cloned = admission.clone();
    let limiter = admission.limiter.as_ref().unwrap();
    assert!(limiter.check_at(&1, 0.0).allowed);
    assert!(cloned.limiter.as_ref().unwrap().check_at(&1, 0.0).allowed);
    let denied = limiter.check_at(&1, 0.0);
    assert!(!denied.allowed);
    assert_eq!(denied.retry_after, 0.5);
    assert!(limiter.check_at(&2, 0.0).allowed);
    assert!(!limiter.check_at(&1, 0.49).allowed);
    assert!(limiter.check_at(&1, 0.5).allowed);
}

#[test]
fn transport_refusals_are_retryable() {
    for (delay, expected) in [(0.0, "1"), (0.1, "1"), (1.01, "2")] {
        let response = refusal(Transport::Http, Refusal::Rate(delay));
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["retry-after"], expected);
    }
    let response = refusal(Transport::Grpc, Refusal::Rate(0.5));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["grpc-status"], "14");
    assert_eq!(response.headers()["content-type"], "application/grpc");
}
