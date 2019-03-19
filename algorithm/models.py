from django.db import models


class AlgorithmTypes(models.Model):
    name = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return self.name


class CipherInstructions(models.Model):
    name = models.CharField(max_length=100, null=True, blank=False)
    algorithm_option = models.CharField(max_length=50, null=True, blank=False)
    form = models.TextField(verbose_name="Form",blank=True)
    algorithm_class = models.ForeignKey(AlgorithmTypes, on_delete=models.CASCADE)

    def __str__(self):
        return self.name
