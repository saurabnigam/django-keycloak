# Generated by Django 2.2.12 on 2020-04-21 18:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('django_keycloak', '0006_remove_client_service_account'),
    ]

    operations = [
        migrations.AddField(
            model_name='realm',
            name='tag',
            field=models.CharField(help_text='use if you want to select between multiple instances of the same realm', max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='realm',
            name='name',
            field=models.CharField(help_text='Name as known on the Keycloak server. This name is used in the API paths of this Realm.', max_length=255),
        ),
    ]
