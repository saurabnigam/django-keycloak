# Generated by Django 2.1.5 on 2019-02-19 20:02

from django.db import migrations


# def forward(apps, schema_editor):
#     Client = apps.get_model('django_keycloak', 'Client')
#     for client in Client.objects.filter(service_account__isnull=False):
#         client.service_account_profile = client.service_account.oidc_profile
#         client.save()
#
#
# def backward(apps, schema_editor):
#     Client = apps.get_model('django_keycloak', 'Client')
#     for client in Client.objects.filter(service_account_profile__isnull=False):
#         client.service_account = client.service_account_profile.user
#         client.save()
#
#
class Migration(migrations.Migration):

    dependencies = [
        ('django_keycloak', '0004_client_service_account_profile'),
    ]

    operations = [
        # migrations.RunPython(forward, backward),
    ]
