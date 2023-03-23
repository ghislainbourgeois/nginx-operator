#!/usr/bin/env python3
# Copyright 2023 Ghislain Bourgeois
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Nginx static website charm."""

import logging

from charms.observability_libs.v1.kubernetes_service_patch import KubernetesServicePatch
from lightkube.models.core_v1 import ServicePort
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus

logger = logging.getLogger(__name__)


class NginxOperatorCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.nginx_pebble_ready, self._on_nginx_pebble_ready)
        self.service_patcher = KubernetesServicePatch(
            charm=self,
            ports=[
                ServicePort(name="http", port=80),
                ServicePort(name="https", port=443),
            ],
            service_type="LoadBalancer",
            service_name="nginx",
        )

    def _on_nginx_pebble_ready(self, event):
        """Define and start a workload using the Pebble API."""
        container = event.workload
        container.add_layer("nginx", self._pebble_layer, combine=True)
        container.replan()
        self.unit.status = ActiveStatus()

    @property
    def _pebble_layer(self):
        """Return a dictionary representing a Pebble layer."""
        return {
            "summary": "nginx pebble layer",
            "description": "pebble config layer for nginx",
            "services": {
                "nginx": {
                    "override": "replace",
                    "summary": "nginx",
                    "command": "nginx -g 'daemon off;'",
                    "startup": "enabled",
                }
            },
        }


if __name__ == "__main__":  # pragma: nocover
    main(NginxOperatorCharm)
