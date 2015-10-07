# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='TestClass',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('field_one', models.BooleanField(default=False)),
                ('field_two', models.BooleanField(default=False)),
                ('field_three', models.BooleanField(default=False)),
                ('field_four', models.BooleanField(default=False)),
                ('field_five', models.BooleanField(default=False)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
    ]
