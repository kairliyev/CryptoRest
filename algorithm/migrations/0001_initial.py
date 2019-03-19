# Generated by Django 2.1.5 on 2019-03-19 07:05

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AlgorithmTypes',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(blank=True, max_length=255, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='CipherInstructions',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, null=True)),
                ('algorithm_option', models.CharField(max_length=50, null=True)),
                ('form', models.TextField(blank=True, verbose_name='Form')),
                ('algorithm_class', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='algorithm.AlgorithmTypes')),
            ],
        ),
    ]
