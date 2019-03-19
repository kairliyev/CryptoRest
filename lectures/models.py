from django.db import models


class Lecture(models.Model):
    form = models.TextField()
    name = models.CharField(max_length=40, null=True, blank=True)
    rating = models.FloatField(default=4.0)
    picture = models.CharField(max_length=255, null=True, blank=False)
    video = models.CharField(max_length=255, null=True, blank=False)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name or str(self.id)

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse('lecture_detail', args=[str(self.id)])
