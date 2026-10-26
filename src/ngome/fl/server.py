"""Flower ServerApp: FedAvg under SecAgg+ with client-side clipping and server-side noise.

Phones clip their own updates because, under secure aggregation, the server only ever sees the
masked sum and so cannot clip individual updates. Run it on a Flower SuperLink, for example
``flower-superlink`` followed by ``flwr run``; the phone ClientApp lives in pesaclarity-app.
"""

from flwr.app import Context
from flwr.server import Grid, LegacyContext, ServerConfig
from flwr.server.strategy import DifferentialPrivacyClientSideFixedClipping, FedAvg, Strategy
from flwr.server.workflow import DefaultWorkflow, SecAggPlusWorkflow
from flwr.serverapp import ServerApp

from ngome.fl.config import FLSettings


def build_strategy(settings: FLSettings) -> Strategy:
    base = FedAvg(
        fraction_evaluate=0.0,
        min_fit_clients=settings.min_cohort_size,
        min_available_clients=settings.min_cohort_size,
    )
    return DifferentialPrivacyClientSideFixedClipping(
        base,
        noise_multiplier=settings.noise_multiplier,
        clipping_norm=settings.clipping_norm,
        num_sampled_clients=settings.min_cohort_size,
    )


def build_workflow(settings: FLSettings) -> DefaultWorkflow:
    return DefaultWorkflow(
        fit_workflow=SecAggPlusWorkflow(
            num_shares=settings.secagg_num_shares,
            reconstruction_threshold=settings.secagg_reconstruction_threshold,
            timeout=settings.round_timeout_seconds,
        )
    )


app = ServerApp()


@app.main()
def main(grid: Grid, context: Context) -> None:
    settings = FLSettings()
    # TODO(fl): load the initial categoriser weights from the pesaclarity-ml release registry
    # and persist the aggregated result; until then this runs rounds with no initial model.
    legacy = LegacyContext(
        context,
        config=ServerConfig(
            num_rounds=settings.num_rounds, round_timeout=settings.round_timeout_seconds
        ),
        strategy=build_strategy(settings),
    )
    build_workflow(settings)(grid, legacy)
