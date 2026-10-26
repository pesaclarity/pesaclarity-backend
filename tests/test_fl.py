import pytest
from pydantic import ValidationError

pytest.importorskip("flwr")

from flwr.server.strategy import DifferentialPrivacyClientSideFixedClipping
from flwr.server.workflow import DefaultWorkflow

from ngome.fl.config import FLSettings
from ngome.fl.server import app, build_strategy, build_workflow


def test_strategy_is_dp_wrapped_with_configured_cohort() -> None:
    settings = FLSettings(min_cohort_size=50, clipping_norm=0.5, noise_multiplier=1.2)
    strategy = build_strategy(settings)
    assert isinstance(strategy, DifferentialPrivacyClientSideFixedClipping)
    assert strategy.clipping_norm == 0.5
    assert strategy.noise_multiplier == 1.2
    assert strategy.num_sampled_clients == 50


def test_workflow_uses_secure_aggregation() -> None:
    workflow = build_workflow(FLSettings())
    assert isinstance(workflow, DefaultWorkflow)
    assert app is not None


def test_secagg_threshold_must_fit_shares() -> None:
    with pytest.raises(ValidationError):
        FLSettings(secagg_num_shares=5, secagg_reconstruction_threshold=6)
