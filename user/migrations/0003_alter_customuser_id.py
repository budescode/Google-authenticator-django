# Generated by Django 4.0 on 2024-02-21 15:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0002_emailtotpdevice'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
    ]