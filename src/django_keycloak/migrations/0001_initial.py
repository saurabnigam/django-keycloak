# Generated by Django 2.0.2 on 2018-03-15 21:15

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True,
                                        serialize=False, verbose_name='ID')),
                ('client_id', models.CharField(max_length=255)),
                ('secret', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Nonce',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True,
                                        serialize=False, verbose_name='ID')),
                ('state', models.UUIDField(default=uuid.uuid4, unique=True)),
                ('redirect_uri', models.CharField(max_length=255)),
                ('next_path', models.CharField(max_length=255, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Realm',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True,
                                        serialize=False, verbose_name='ID')),
                ('name', models.CharField(
                    help_text='Name as known on the Keycloak server. This '
                              'name is used in the API paths of this Realm.',
                    max_length=255, unique=True)),
                ('_certs', models.TextField()),
                ('_well_known_oidc', models.TextField(blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True,
                                        serialize=False, verbose_name='ID')),
                ('reference', models.CharField(max_length=50)),
                ('client', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='roles', to='django_keycloak.Client')),
                ('permission', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    to='auth.Permission')),
            ],
        ),
        migrations.CreateModel(
            name='Server',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True,
                                        serialize=False, verbose_name='ID')),
                ('url', models.CharField(max_length=255)),
                ('internal_url', models.CharField(
                    blank=True,
                    help_text='URL on internal netwerk calls. For example '
                              'when used with Docker Compose. Only supply '
                              'when internal calls should go to a different '
                              'url as the end-user will communicate with.',
                    max_length=255, null=True)),
            ],
        ),
    ]

    if not getattr(settings, 'AUTH_ENABLE_REMOTE_USER', False):
        # Only add oidc_profile to user if AUTH_USER_MODEL is set,
        # Otherwise we will assume that no user model is stored in the application
        operations.append(
            migrations.CreateModel(
                name='OpenIdConnectProfile',
                fields=[
                    ('id', models.AutoField(auto_created=True, primary_key=True,
                                            serialize=False, verbose_name='ID')),
                    ('access_token', models.TextField(null=True)),
                    ('expires_before', models.DateTimeField(null=True)),
                    ('refresh_token', models.TextField(null=True)),
                    ('refresh_expires_before', models.DateTimeField(null=True)),
                    ('sub', models.CharField(max_length=255, unique=True)),
                ],
            )
        )

        operations.append(
            migrations.AddField(
                model_name='openidconnectprofile',
                name='user',
                field=models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='oidc_profile', to=settings.AUTH_USER_MODEL),
            )
        )

        operations.append(
            migrations.AddField(
                model_name='openidconnectprofile',
                name='realm',
                field=models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='openid_profiles', to='django_keycloak.Realm'),
            )
        )

        operations.append(
            migrations.AddField(
                model_name='client',
                name='service_account',
                field=models.OneToOneField(
                    null=True, on_delete=django.db.models.deletion.CASCADE,
                    related_name='keycloak_client', to=settings.AUTH_USER_MODEL),
            )
        )

    else:
        operations.append(
            migrations.CreateModel(
                name='RemoteUserOpenIdConnectProfile',
                fields=[
                    ('id', models.AutoField(auto_created=True, primary_key=True,
                                            serialize=False, verbose_name='ID')),
                    ('access_token', models.TextField(null=True)),
                    ('expires_before', models.DateTimeField(null=True)),
                    ('refresh_token', models.TextField(null=True)),
                    ('refresh_expires_before', models.DateTimeField(null=True)),
                    ('sub', models.CharField(max_length=255, unique=True)),
                ],
            )
        )

        operations.append(migrations.AddField(
            model_name='remoteuseropenidconnectprofile',
            name='realm',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='openid_profiles', to='django_keycloak.Realm'),
        ))

    operations.append(
        migrations.AddField(
            model_name='realm',
            name='server',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='realms', to='django_keycloak.Server'),
        )
    )

    operations.append(
        migrations.AddField(
            model_name='client',
            name='realm',
            field=models.OneToOneField(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='client', to='django_keycloak.Realm'),
        )
    )

    operations.append(migrations.AlterUniqueTogether(
        name='role',
        unique_together={('client', 'permission')},
        )
    )
