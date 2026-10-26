"""Federated-learning settings (prefix ``NGOME_FL_``).

The privacy values are placeholders. Real ones come from the privacy budget published with
each model release in pesaclarity-ml, not from this file.
"""

from typing import Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class FLSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NGOME_FL_", env_file=".env", extra="ignore")

    num_rounds: int = Field(default=3, ge=1)
    min_cohort_size: int = Field(
        default=100, ge=2, description="Fewest phones that may contribute to a round."
    )
    clipping_norm: float = Field(default=1.0, gt=0, description="L2 bound applied on the phone.")
    noise_multiplier: float = Field(default=1.0, ge=0, description="Gaussian noise, server side.")
    secagg_num_shares: int = Field(default=20, ge=2, description="SecAgg+ neighbours per phone.")
    secagg_reconstruction_threshold: int = Field(
        default=14, ge=2, description="Shares needed to recover a dropped phone's mask."
    )
    round_timeout_seconds: float | None = Field(default=600, gt=0)

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.secagg_reconstruction_threshold > self.secagg_num_shares:
            raise ValueError("secagg_reconstruction_threshold cannot exceed secagg_num_shares")
        if self.secagg_num_shares > self.min_cohort_size:
            raise ValueError("secagg_num_shares cannot exceed min_cohort_size")
        return self
