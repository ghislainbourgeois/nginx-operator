# Copyright 2023 Ghislain Bourgeois
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import pathlib
import tempfile
from unittest.mock import Mock, patch

import pytest
from charm import NginxOperatorCharm
from charms.tls_certificates_interface.v2.tls_certificates import (
    generate_csr,
    generate_private_key,
)
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, UnknownStatus, WaitingStatus
from scenario.state import Container, Mount, Relation, State


def _config_changed_event(_):
    return "config_changed"


def _relation_joined_event(x):
    return x.joined_event


class TestCharm:
    @patch("charm.KubernetesServicePatch", new=Mock)
    def test_when_pebble_ready_then_nginx_is_started(self):
        container = Container(name="nginx", can_connect=True)
        out = State(
            containers=[
                container,
            ]
        ).trigger(container.pebble_ready_event, NginxOperatorCharm)

        expected_layer = {
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
        assert out.containers[0].layers["nginx"].to_dict() == expected_layer
        assert out.status.unit_history == [
            UnknownStatus(),
            MaintenanceStatus("Configuring nginx service"),
        ]
        assert out.status.unit == ActiveStatus()

    @patch("charm.KubernetesServicePatch", new=Mock)
    def test_cannot_connect_when_config_changed_then_event_is_defered(self):
        container = Container(name="nginx", can_connect=False)
        out = State(
            containers=[
                container,
            ]
        ).trigger("config_changed", NginxOperatorCharm)

        assert out.deferred[0].name == "config_changed"
        assert out.status.unit == WaitingStatus("Waiting for nginx container to be ready")

    @patch("charm.KubernetesServicePatch", new=Mock)
    def test_can_connect_and_no_peer_relation_when_config_changed_then_event_is_defered(self):
        container = Container(name="nginx", can_connect=True)
        out = State(
            containers=[
                container,
            ]
        ).trigger("config_changed", NginxOperatorCharm)

        assert out.deferred[0].name == "config_changed"
        assert out.status.unit == WaitingStatus("Waiting for peer relation to be created")

    @patch("charm.KubernetesServicePatch", new=Mock)
    def test_can_connect_and_peer_relation_and_no_certificates_relation_when_config_changed_then_event_is_defered(
        self,
    ):  # noqa E501
        container = Container(name="nginx", can_connect=True)
        peer_relation = Relation("replicas")
        out = State(
            containers=[
                container,
            ],
            relations=[peer_relation],
        ).trigger("config_changed", NginxOperatorCharm)

        assert out.deferred[0].name == "config_changed"
        assert out.status.unit == WaitingStatus("Waiting for certificates relation to be created")

    @patch("charm.KubernetesServicePatch", new=Mock)
    @pytest.mark.parametrize("event", [_config_changed_event, _relation_joined_event])
    def test_can_connect_and_peer_relation_and_certificates_relation_and_no_fqdn_when_config_changed_then_status_is_blocked(
        self, event
    ):  # noqa E501
        container = Container(name="nginx", can_connect=True)
        peer_relation = Relation("replicas")
        certificates_relation = Relation("certificates")
        out = State(
            containers=[
                container,
            ],
            relations=[peer_relation, certificates_relation],
        ).trigger(event(certificates_relation), NginxOperatorCharm)

        assert len(out.deferred) == 0
        assert out.status.unit == BlockedStatus("FQDN configuration missing")

    @patch("charm.KubernetesServicePatch", new=Mock)
    @pytest.mark.parametrize("event", [_config_changed_event, _relation_joined_event])
    def test_no_private_key_when_config_changed_then_private_key_is_created(
        self, event
    ):  # noqa E501
        local_file = tempfile.NamedTemporaryFile()
        container = Container(
            name="nginx",
            can_connect=True,
            mounts={"local": Mount("/etc/nginx/ssl/cert.key", local_file.name)},
        )
        peer_relation = Relation("replicas")
        certificates_relation = Relation("certificates")
        out = State(
            leader=True,
            containers=[
                container,
            ],
            relations=[peer_relation, certificates_relation],
            config={"fqdn": "test.fqdn"},
        ).trigger(event(certificates_relation), NginxOperatorCharm)

        assert len(out.deferred) == 0
        assert len(local_file.read()) > 0
        assert "private_key" in out.relations[0].local_app_data
        assert out.status.unit == WaitingStatus("Waiting for requested certificate")

    @patch("charm.KubernetesServicePatch", new=Mock)
    @pytest.mark.parametrize("event", [_config_changed_event, _relation_joined_event])
    def test_private_key_when_config_changed_then_private_key_is_not_recreated(
        self, event
    ):  # noqa E501
        local_file = tempfile.NamedTemporaryFile()
        container = Container(
            name="nginx",
            can_connect=True,
            mounts={"local": Mount("/etc/nginx/ssl/cert.key", local_file.name)},
        )
        peer_relation = Relation("replicas")
        peer_relation.local_app_data.update({"private_key": generate_private_key().decode()})
        certificates_relation = Relation("certificates")
        out = State(
            leader=True,
            containers=[
                container,
            ],
            relations=[peer_relation, certificates_relation],
            config={"fqdn": "test.fqdn"},
        ).trigger(event(certificates_relation), NginxOperatorCharm)

        assert len(out.deferred) == 0
        assert (
            out.relations[0].local_app_data["private_key"]
            == peer_relation.local_app_data["private_key"]
        )
        assert out.status.unit == WaitingStatus("Waiting for requested certificate")

    @patch("charm.KubernetesServicePatch", new=Mock)
    @pytest.mark.parametrize("event", [_config_changed_event, _relation_joined_event])
    def test_private_key_when_config_changed_then_csr_is_sent_in_relation_data(
        self, event
    ):  # noqa E501
        container = Container(name="nginx", can_connect=True)
        peer_relation = Relation("replicas")
        peer_relation.local_app_data.update({"private_key": generate_private_key().decode()})
        certificates_relation = Relation("certificates")
        out = State(
            leader=True,
            containers=[
                container,
            ],
            relations=[peer_relation, certificates_relation],
            config={"fqdn": "test.fqdn"},
        ).trigger(event(certificates_relation), NginxOperatorCharm)

        assert len(out.deferred) == 0
        assert (
            "BEGIN CERTIFICATE REQUEST"
            in out.relations[1].local_unit_data["certificate_signing_requests"]
        )
        assert out.status.unit == WaitingStatus("Waiting for requested certificate")

    @patch("charm.KubernetesServicePatch", new=Mock)
    def test_no_peer_relation_when_certificate_available_then_event_is_deferred(self):  # noqa E501
        etc_nginx = tempfile.TemporaryDirectory()
        container = Container(
            name="nginx",
            can_connect=True,
            mounts={"local": Mount("/etc/nginx", etc_nginx.name)},
        )
        container = Container(name="nginx", can_connect=True)
        private_key = generate_private_key().decode()
        csr = generate_csr(
            private_key=private_key.encode(),
            subject="test.fqdn",
        )
        certificates_relation = Relation(
            endpoint="certificates",
            remote_app_name="remote",
            local_unit_data={
                "certificate_signing_requests": [{"certificate_signing_request": csr.decode()}]
            },
            remote_app_data={
                "certificates": [
                    {
                        "ca": "test-ca",
                        "chain": ["test-chain"],
                        "certificate": "test-certificate",
                        "certificate_signing_request": csr.decode(),
                    }
                ]
            },
        )
        out = State(
            leader=True,
            containers=[
                container,
            ],
            relations=[certificates_relation],
            config={"fqdn": "test.fqdn"},
        ).trigger(certificates_relation.changed_event, NginxOperatorCharm)

        assert out.deferred[0].name == "certificate_available"
        assert out.status.unit == WaitingStatus("Waiting for peer relation to be created")

    @patch("charm.KubernetesServicePatch", new=Mock)
    def test_when_certificate_available_then_tls_config_is_pushed(self):  # noqa E501
        nginx_dir = tempfile.TemporaryDirectory()
        container = Container(
            name="nginx",
            can_connect=True,
            mounts={"nginx_dir": Mount("/etc/nginx", nginx_dir.name)},
        )
        private_key = generate_private_key().decode()
        csr = generate_csr(
            private_key=private_key.encode(),
            subject="test.fqdn",
        )
        peer_relation = Relation(
            endpoint="replicas", local_app_data={"private_key": private_key, "csr": csr.decode()}
        )
        certificates_relation = Relation(
            endpoint="certificates",
            remote_app_name="remote",
            local_unit_data={
                "certificate_signing_requests": [{"certificate_signing_request": csr.decode()}]
            },
            remote_app_data={
                "certificates": [
                    {
                        "ca": "test-ca",
                        "chain": ["test-chain"],
                        "certificate": "test-certificate",
                        "certificate_signing_request": csr.decode(),
                    }
                ]
            },
        )
        out = State(
            leader=True,
            containers=[
                container,
            ],
            relations=[peer_relation, certificates_relation],
            config={"fqdn": "test.fqdn"},
        ).trigger(certificates_relation.changed_event, NginxOperatorCharm)

        assert out.status.unit == ActiveStatus()
        with (
            open(pathlib.Path(nginx_dir.name) / "conf.d" / "tls.conf") as tlsconf,
            open(pathlib.Path(__file__).parent / "expected_tls.conf") as expected,
        ):
            assert tlsconf.read() == expected.read()
        with open(pathlib.Path(nginx_dir.name) / "ssl" / "cert.crt") as cert:
            assert cert.read() == "test-certificate"

    @patch("charm.KubernetesServicePatch", new=Mock)
    def test_has_certificate_when_certificate_invalidated_then_certificate_is_refreshed(
        self,
    ):  # noqa E501
        container = Container(
            name="nginx",
            can_connect=True,
        )
        private_key = generate_private_key().decode()
        csr = generate_csr(
            private_key=private_key.encode(),
            subject="test.fqdn",
        )
        peer_relation = Relation(
            endpoint="replicas", local_app_data={"private_key": private_key, "csr": csr.decode()}
        )
        certificates_relation = Relation(
            endpoint="certificates",
            remote_app_name="remote",
            local_unit_data={
                "certificate_signing_requests": [{"certificate_signing_request": csr.decode()}]
            },
            remote_app_data={
                "certificates": [
                    {
                        "ca": "test-ca",
                        "chain": ["test-chain"],
                        "certificate": "test-certificate",
                        "certificate_signing_request": csr.decode(),
                        "revoked": True,
                    }
                ]
            },
        )
        out = State(
            leader=True,
            containers=[
                container,
            ],
            relations=[peer_relation, certificates_relation],
            config={"fqdn": "test.fqdn"},
        ).trigger(certificates_relation.changed_event, NginxOperatorCharm)

        assert out.status.unit == WaitingStatus("Waiting for requested certificate")

    @patch("charm.KubernetesServicePatch", new=Mock)
    def test_fqdn_config_removed_when_certificate_invalidated_then_status_is_blocked(
        self,
    ):  # noqa E501
        container = Container(
            name="nginx",
            can_connect=True,
        )
        private_key = generate_private_key().decode()
        csr = generate_csr(
            private_key=private_key.encode(),
            subject="test.fqdn",
        )
        peer_relation = Relation(
            endpoint="replicas", local_app_data={"private_key": private_key, "csr": csr.decode()}
        )
        certificates_relation = Relation(
            endpoint="certificates",
            remote_app_name="remote",
            local_unit_data={
                "certificate_signing_requests": [{"certificate_signing_request": csr.decode()}]
            },
            remote_app_data={
                "certificates": [
                    {
                        "ca": "test-ca",
                        "chain": ["test-chain"],
                        "certificate": "test-certificate",
                        "certificate_signing_request": csr.decode(),
                        "revoked": True,
                    }
                ]
            },
        )
        out = State(
            leader=True,
            containers=[
                container,
            ],
            relations=[peer_relation, certificates_relation],
            config={"fqdn": ""},
        ).trigger(certificates_relation.changed_event, NginxOperatorCharm)

        assert out.status.unit == BlockedStatus("FQDN configuration missing")
