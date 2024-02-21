# Generated by Django 4.0 on 2024-02-21 14:57

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('otp_totp', '0002_auto_20190420_0723'),
        ('user', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='EmailTOTPDevice',
            fields=[
                ('totpdevice_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='otp_totp.totpdevice')),
                ('email', models.EmailField(max_length=254, unique=True)),
            ],
            options={
                'abstract': False,
            },
            bases=('otp_totp.totpdevice', models.Model),
        ),
    ]
