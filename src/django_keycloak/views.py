# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from django.shortcuts import resolve_url

try:
    from urllib.parse import urljoin  # noqa: F401
except ImportError:
    from urlparse import urljoin  # noqa: F401

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.http.response import (
    HttpResponseBadRequest,
    HttpResponseServerError,
    HttpResponseRedirect
)
from django.urls.base import reverse
from django.views.generic.base import RedirectView

from django_keycloak.models import Nonce
from django_keycloak.auth import remote_user_login


logger = logging.getLogger(__name__)


class Login(RedirectView):

    def get_redirect_url(self, *args, **kwargs):

        nonce = Nonce.objects.create(
            redirect_uri=self.request.build_absolute_uri(
                location=reverse('login-complete')),
            next_path=self.request.GET.get('next'))

        self.request.session['oidc_state'] = str(nonce.state)

        authorization_url = self.request.realm.keycloak_openid\
            .authorization_url(
                redirect_uri=nonce.redirect_uri,
                scope='openid given_name family_name email uma_authorization',
                state=str(nonce.state)
            )

        if self.request.realm.internal_server_url:
            authorization_url = authorization_url.replace(
                self.request.realm.internal_server_url,
                self.request.realm.server_url,
                1
            )

        logger.debug(authorization_url)

        return authorization_url


class LoginComplete(RedirectView):

    def get(self, *args, **kwargs):
        if 'error' in self.request.GET:
            return HttpResponseServerError(self.request.GET['error'])

        if 'code' not in self.request.GET and 'state' not in self.request.GET:
            return HttpResponseBadRequest()

        if self.request.GET['state'] != self.request.session['oidc_state']:
            return HttpResponseBadRequest()

        nonce = Nonce.objects.get(state=self.request.GET['state'])

        user = authenticate(request=self.request,
                            code=self.request.GET['code'],
                            redirect_uri=nonce.redirect_uri)

        if hasattr(settings, 'AUTH_REMOTE_USER_MODEL'):
            remote_user_login(self.request, user)
        else:
            login(self.request, user)

        nonce.delete()
        return HttpResponseRedirect(nonce.next_path or '/')


class Logout(RedirectView):

    def get_redirect_url(self, *args, **kwargs):
        # TODO: oidc_profile is not stored in the user, probably needs to be changed
        if hasattr(self.request.user, 'oidc_profile'):
            self.request.realm.keycloak_openid.logout(
                self.request.user.oidc_profile.refresh_token
            )
        logout(self.request)

        if settings.LOGOUT_REDIRECT_URL:
            return resolve_url(settings.LOGOUT_REDIRECT_URL)

        return reverse('keycloak_login')
