"""Immutable timing limits for signed authorization policy v1."""
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthorizationTimingPolicy:
    max_review_age_seconds: int
    max_active_lease_seconds: int

    def __post_init__(self):
        if (type(self.max_review_age_seconds) is not int or type(self.max_active_lease_seconds) is not int
                or not 0 <= self.max_review_age_seconds <= 300
                or not 1 <= self.max_active_lease_seconds <= 300):
            raise ValueError("review age must be a nonnegative integer and lease lifetime a positive integer, both no greater than v1 ceilings")


AUTHORIZATION_TIMING_V1 = AuthorizationTimingPolicy(
    max_review_age_seconds=300,
    max_active_lease_seconds=300,
)
