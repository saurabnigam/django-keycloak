from django.test import TestCase, RequestFactory

from django_keycloak.factories import ServerFactory, RealmFactory
from django_keycloak.tests.mixins import MockTestCaseMixin
from django_keycloak.models import Realm, Server
from django_keycloak.middleware import get_realm
from django.test.utils import override_settings

import django_keycloak.services.realm


class ServicesRealmGetRealmApiClientTestCase(
        MockTestCaseMixin, TestCase):

    def setUp(self):
        self.server = ServerFactory(
            url='https://some-url',
            internal_url=''
        )

        self.realm = RealmFactory(
            server=self.server,
            name='test-realm'
        )

        self.request_factory = RequestFactory()

    def test_get_realm_api_client(self):
        """
        Case: a realm api client is requested for a realm on a server without
        internal_url.
        Expected: a KeycloakRealm client is returned with settings based on the
        provided realm. The server_url in the client is the provided url.
        """
        client = django_keycloak.services.realm.\
            get_realm_api_client(realm=self.realm)

        self.assertEqual(client.server_url, self.server.url)
        self.assertEqual(client.realm_name, self.realm.name)

    def test_get_realm_api_client_with_internal_url(self):
        """
        Case: a realm api client is requested for a realm on a server with
        internal_url.
        Expected: a KeycloakRealm client is returned with settings based on the
        provided realm. The server_url in the client is the provided url.
        """
        self.server.internal_url = 'https://some-internal-url'

        client = django_keycloak.services.realm.\
            get_realm_api_client(realm=self.realm)

        self.assertEqual(client.server_url, self.server.internal_url)
        self.assertEqual(client.realm_name, self.realm.name)

    def test_get_realm_only_one(self):

        request = self.request_factory.get('/')

        realm = get_realm(request)
        self.assertEqual(realm.name, "test-realm")

    @override_settings(KEYCLOAK_USE_REALM="Test")
    def test_get_specified_realm(self):
        '''check that if there are mutliple realms, the realm with tag specified in KEYCLOAK_USE_REALM is chosen'''

        server = Server.objects.create(url="http://server")
        Realm.objects.create(name="Realm 1", tag="Production", server=server)
        Realm.objects.create(name="Realm 1", tag="Test", server=server)
        Realm.objects.create(name="Realm 1", tag="Dev", server=server)

        request = self.request_factory.get('/')

        realm = get_realm(request)
        self.assertEqual(realm.name, "Realm 1")
        self.assertEqual(realm.tag, "Test")