# Generated by Django 2.1.5 on 2019-02-19 20:22

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('django_keycloak', '0005_auto_20190219_2002'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='client',
            name='service_account',
        ),
    ]