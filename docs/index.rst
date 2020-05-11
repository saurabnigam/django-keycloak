===========================================
Welcome to Django Keycloak's documentation!
===========================================

.. toctree::
   :hidden:
   :caption: Scenario's
   :maxdepth: 2

   scenario/example_project
   scenario/local_user_setup
   scenario/remote_user_setup
   scenario/initial_setup
   scenario/migrating
   scenario/permissions_by_roles
   scenario/permissions_by_resources_and_scopes
   scenario/multi_tenancy

Django Keycloak adds Keycloak support to your Django project. It's build on top
of `Django's authentication system <https://docs.djangoproject.com/en/1.11/ref/contrib/auth/>`_.
It works side-by-side with the standard Django authentication implementation and
has tools to migrate your current users and permissions to Keycloak.

Features
========

- Multi tenancy support
- Permissions by roles or by resource/scope
- Choose if you want to create a local User model for every logged in identity or not.

Read :ref:`example_project` to quickly test this project.

.. note:: The documentation and the example project are all based on
    Keycloak version 3.4 since that is the latest version which is commercially
    supported by Red Hat (SSO).

Installation
============

Install requirement.

.. code-block:: bash

    $ pip install git+https://github.com/Peter-Slump/django-keycloak.git

Setup
=====

Some settings are always required and some other settings are dependant on how
you want to integrate Keycloak in your project.

Add `django-keycloak` to your installed apps, add the authentication back-end,
add the middleware, configure the urls and point to the correct login page.

.. code-block:: python

    # your-project/settings.py
    INSTALLED_APPS = [
        ....

        'django_keycloak.apps.KeycloakAppConfig'
    ]

    MIDDLEWARE = [
        ...

        'django_keycloak.middleware.BaseKeycloakMiddleware',
    ]

    AUTHENTICATION_BACKENDS = [
        ...

        'django_keycloak.auth.backends.KeycloakAuthorizationCodeBackend',
    ]

    LOGIN_URL = 'keycloak_login'

.. code-block:: python

    # your-project/urls.py
    ...

    urlpatterns = [
        ...

        url(r'^keycloak/', include('django_keycloak.urls')),
    ]


Before you actually start using Django Keycloak make an educated choice between
:ref:`local_user_setup` and :ref:`remote_user_setup`.

Then walk through the :ref:`initial_setup` to found out how to link your
Keycloak instance to your Django project.

If you don't want to take all that effort please read about :ref:`example_project`

Customisation
=============

If there are additional user attributes being passed in the access token that should update the user instance, add a new method to the user called update_or_create_from_token.  If this method exists it will automatically be called and passed the token.  Example::

    @classmethod
    def update_or_create_from_token(cls, token):

        # get or create user
        username = token['sub']
        try:
            user = cls.objects.get(username=username)
        except cls.DoesNotExist:
            user = cls.objects.create_user(username=username, email=token['email'])

        # see if we need to update

        # if we have org groups, assume they are organisations this user belongs to.
        # for now we are only handling one organisation per user
        org_groups = [item for item in token['groups'] if item[:4] == "/org"]
        org_codes = [code.split("/")[2] for code in org_groups]
        org_code = org_codes[0] if org_codes else None


        if user.first_name != token.get('given_name', '') or \
            user.last_name != token.get('family_name', '') or \
            user.organisation_id != org_code:

            user.first_name = token.get('given_name', '')
            user.last_name = token.get('family_name', '')
            user.organisation_id = org_code

            user.save(update_fields=['first_name', 'last_name', 'organisation_id'])


Usage
=====

For requiring a logged in user you can just use the `standard Django
functionality <https://docs.djangoproject.com/en/1.11/topics/auth/default/#limiting-access-to-logged-in-users>`_.
This also counts for `enforcing permissions <https://docs.djangoproject.com/en/1.11/topics/auth/default/#the-permission-required-decorator>`_.

This app makes use of the `Python Keycloak client <https://github.com/Peter-Slump/python-keycloak-client>`_
