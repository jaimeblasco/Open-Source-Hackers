from django.db import models

# Create your models here.
class Rule(models.Model):
    name = models.CharField(max_length=200)
    rule = models.TextField()
    description = models.CharField(max_length=200)


    


