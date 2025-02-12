import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.utils import timezone
from jose.exceptions import (
    ExpiredSignatureError,
    JWTClaimsError,
    JWTError,
)
from keycloak.exceptions import KeycloakClientError
import django_keycloak.services.oidc_profile


logger = logging.getLogger(__name__)


class KeycloakAuthorizationBase(object):

    def get_user(self, user_id):
        UserModel = get_user_model()

        try:
            user = UserModel.objects.select_related('oidc_profile__realm').get(
                pk=user_id)
        except UserModel.DoesNotExist:
            return None

        if user.get_profile().refresh_expires_before > timezone.now():
            return user

        return None

    def get_all_permissions(self, user_obj, obj=None):
        if not user_obj.is_active or user_obj.is_anonymous or obj is not None:
            return set()
        if not hasattr(user_obj, '_keycloak_perm_cache'):
            user_obj._keycloak_perm_cache = self.get_keycloak_permissions(
                user_obj=user_obj)
        return user_obj._keycloak_perm_cache

    def get_keycloak_permissions(self, user_obj):
        if not hasattr(user_obj, 'oidc_profile'):
            return set()

        rpt_decoded = django_keycloak.services.oidc_profile\
            .get_entitlement(oidc_profile=user_obj.oidc_profile)

        return rpt_decoded['authorization'].get('permissions', [])

    def has_perm(self, user_obj, perm, obj=None):
        if '.' in perm:
            # Permission is formatted as <resource>.<scope>
            # Split the permission into separate resource and scope
            resource, scope = perm.split('.', 1)
        else:
            # Permission is only a resource
            # Can't split
            resource = perm
            scope = ''

        return perm in granted_perms

        for p in granted_perms:
            if p['resource_set_name'] == resource and not p.get('scopes'):
                return True

            if p['resource_set_name'] == resource \
                    and scope in p.get('scopes', {}):
                return True

        return False


class KeycloakAuthorizationCodeBackend(KeycloakAuthorizationBase):

    def authenticate(self, request, code, redirect_uri):

        if not hasattr(request, 'realm'):
            raise ImproperlyConfigured(
                'Add BaseKeycloakMiddleware to middlewares')

        keycloak_openid_profile = django_keycloak.services\
            .oidc_profile.update_or_create_from_code(
                client=request.realm.client,
                code=code,
                redirect_uri=redirect_uri
            )

        return keycloak_openid_profile.user


class KeycloakPasswordCredentialsBackend(KeycloakAuthorizationBase):

    def authenticate(self, request, username, password):

        if not hasattr(request, 'realm'):
            raise ImproperlyConfigured(
                'Add BaseKeycloakMiddleware to middlewares')

        if not request.realm:
            # If request.realm does exist, but it is filled with None, we
            # can't authenticate using Keycloak
            return None

        try:
            keycloak_openid_profile = django_keycloak.services\
                .oidc_profile.update_or_create_from_password_credentials(
                    client=request.realm.client,
                    username=username,
                    password=password
                )
        except KeycloakClientError:
            logger.debug('KeycloakPasswordCredentialsBackend: failed to '
                         'authenticate.')
        else:
            return keycloak_openid_profile.user

        return None


class KeycloakIDTokenAuthorizationBackend(KeycloakAuthorizationBase):

    def authenticate(self, request, access_token):

        if not hasattr(request, 'realm'):
            raise ImproperlyConfigured(
                'Add BaseKeycloakMiddleware to middlewares')

        try:
            oidc_profile = django_keycloak.services.oidc_profile\
                .get_or_create_from_id_token(
                    client=request.realm.client,
                    id_token=access_token
                )
        except ExpiredSignatureError:
            # If the signature has expired.
            logger.debug('KeycloakBearerAuthorizationBackend: failed to '
                         'authenticate due to an expired access token.')
        except JWTClaimsError as e:
            logger.debug('KeycloakBearerAuthorizationBackend: failed to '
                         'authenticate due to failing claim checks: "%s"'
                         % str(e))
        except JWTError:
            # The signature is invalid in any way.
            logger.debug('KeycloakBearerAuthorizationBackend: failed to '
                         'authenticate due to a malformed access token.')
        else:
            return oidc_profile.user

        return None


class KeycloakDRFAuthorizationBackend(KeycloakAuthorizationBase):
    keyword = "bearer"

    def authenticate(self, request):

        auth = request.headers.get('Authorization')
        provided_origin = request.headers.get('Origin')


        if not auth:
            return None


        key, token = auth.split()

        if key.lower() != self.keyword.lower():
            msg = _('Invalid key for Authorization, expecting Bearer')
            raise PermissionDenied(msg)

        elif len(token) < 10 or len(token) > 2000:
            msg = _('Invalid token header.')
            raise PermissionDenied(msg)


        if not hasattr(request, 'realm'):
            raise ImproperlyConfigured(
                'Add BaseKeycloakMiddleware to middlewares')

        try:
            oidc_profile = django_keycloak.services.oidc_profile\
                .get_or_create_from_id_token(
                    client=request.realm.client,
                    id_token=token
                )
        except ExpiredSignatureError:
            # If the signature has expired.
            msg = _('KeycloakBearerAuthorizationBackend: failed to '
                         'authenticate due to an expired access token.')
            raise PermissionDenied(msg)
        except JWTClaimsError as e:
            msg = _('KeycloakBearerAuthorizationBackend: failed to '
                         'authenticate due to failing claim checks: "%s"'
                         % str(e))
            raise PermissionDenied(msg)
        except JWTError:
            # The signature is invalid in any way.
            msg = _('KeycloakBearerAuthorizationBackend: failed to '
                         'authenticate due to a malformed access token.')
            raise PermissionDenied(msg)
        except Exception as e:
            msg = _(f'Unexpected error in authentication {e}')
            raise PermissionDenied(msg)
        else:
            return (oidc_profile.user, None)

        return None
