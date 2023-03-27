#!/usr/bin/env python3
# Copyright 2023 Ghislain Bourgeois
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Nginx static website charm."""

import logging
import pathlib

from charms.observability_libs.v1.kubernetes_service_patch import KubernetesServicePatch
from charms.tls_certificates_interface.v2.tls_certificates import (
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from lightkube.models.core_v1 import ServicePort
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus

logger = logging.getLogger(__name__)


class NginxOperatorCharm(CharmBase):
    """Charm nginx service."""

    def __init__(self, *args):
        super().__init__(*args)
        self._container = self.unit.get_container("nginx")
        self.certificates = TLSCertificatesRequiresV2(self, "certificates")

        self.framework.observe(self.on.nginx_pebble_ready, self._on_nginx_pebble_ready)
        self.framework.observe(self.on.config_changed, self._request_certificate)
        self.framework.observe(self.on.certificates_relation_joined, self._request_certificate)
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.certificates.on.certificate_expiring, self._request_certificate_renewal
        )
        self.framework.observe(
            self.certificates.on.certificate_invalidated, self._request_certificate_renewal
        )
        self.framework.observe(
            self.certificates.on.all_certificates_invalidated,
            self._request_certificate_renewal,
        )

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
        """Define and start nginx service using the Pebble API."""
        self.unit.status = MaintenanceStatus("Configuring nginx service")
        self._container.add_layer("nginx", self._pebble_layer, combine=True)
        self._container.replan()
        self._container.restart("nginx")
        self.unit.status = ActiveStatus()

    def _request_certificate(self, event):
        """Request a certificate over the tls-certificates interface.

        It will first generate a private key if not already present, create a CSR
        and send that CSR over the relation.
        """
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting for nginx container to be ready")
            event.defer()
            return
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        if not self.model.get_relation("certificates"):
            self.unit.status = WaitingStatus("Waiting for certificates relation to be created")
            event.defer()
            return
        if not self._fqdn:
            self.unit.status = BlockedStatus("FQDN configuration missing")
            return
        if "private_key" not in replicas_relation.data[self.app]:
            self._generate_private_key()
        private_key = replicas_relation.data[self.app].get("private_key")
        csr = generate_csr(
            private_key=private_key.encode(),
            subject=self._fqdn,
        )
        replicas_relation.data[self.app].update({"csr": csr.decode()})
        self.certificates.request_certificate_creation(certificate_signing_request=csr)
        self.unit.status = WaitingStatus("Waiting for requested certificate")

    def _request_certificate_renewal(self, event):
        """Request a new certificate by providing a new CSR on the tls-certificates relation."""
        if not self._fqdn:
            self.unit.status = BlockedStatus("FQDN configuration missing")
            return
        replicas_relation = self.model.get_relation("replicas")
        old_csr = replicas_relation.data[self.app].get("csr")
        private_key = replicas_relation.data[self.app].get("private_key")
        csr = generate_csr(
            private_key=private_key.encode(),
            subject=self._fqdn,
        )
        replicas_relation.data[self.app].update({"csr": csr.decode()})
        self.certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr.encode(), new_certificate_signing_request=csr
        )
        self.unit.status = WaitingStatus("Waiting for requested certificate")

    def _on_certificate_available(self, event):
        """Handle provided certificate.

        When a certificate becomes available, push it to the container,
        configure nginx for TLS, store the certificate in a peer relation and
        force reconfiguration of nginx.
        """
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        self._container.push(
            path="/etc/nginx/ssl/cert.crt", source=event.certificate.encode(), make_dirs=True
        )
        self._push_tls_config()
        replicas_relation.data[self.app].update({"certificate": event.certificate})
        self._on_nginx_pebble_ready(event)

    def _generate_private_key(self):
        """Generate a private key.

        Push it to the container and store it in the peer relation.
        """
        private_key = generate_private_key()
        self._container.push(path="/etc/nginx/ssl/cert.key", source=private_key, make_dirs=True)
        replicas_relation = self.model.get_relation("replicas")
        replicas_relation.data[self.app].update({"private_key": private_key.decode()})

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

    @property
    def _fqdn(self):
        """Property to get the FQDN from the charm configuration."""
        return self.model.config.get("fqdn")

    def _push_tls_config(self) -> None:
        """Push tls server configuration to /etc/nginx/conf.d/tls.conf."""
        with open(pathlib.Path(__file__).parent / "tls.conf") as config:
            self._container.push(
                path="/etc/nginx/conf.d/tls.conf", source=config.read(), make_dirs=True
            )


if __name__ == "__main__":  # pragma: nocover
    main(NginxOperatorCharm)
