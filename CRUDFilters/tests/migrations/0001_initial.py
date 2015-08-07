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
                ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True, serialize=False)),
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
